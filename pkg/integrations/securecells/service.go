package securecells

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aethelred/aethelred/pkg/confidential"
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
	secureCellTool                                                                       = "secure_cells"
	secureCellCreateAction                                                               = "secure_cells.create"
	secureCellActivateAction                                                             = "secure_cells.activate"
	secureCellSessionStartAction                                                         = "secure_cells.session.start"
	secureCellSessionThreadStartAction                                                   = "secure_cells.session.thread.start"
	secureCellSessionThreadMessageAction                                                 = "secure_cells.session.thread.message"
	secureCellSessionThreadDecisionCreateAction                                          = "secure_cells.session.thread.decision.create"
	secureCellSessionThreadDecisionApproveAction                                         = "secure_cells.session.thread.decision.approve"
	secureCellSessionThreadDecisionCommentAction                                         = "secure_cells.session.thread.decision.comment"
	secureCellSessionThreadDecisionDelegateAction                                        = "secure_cells.session.thread.decision.delegate"
	secureCellSessionThreadDecisionEscalateAction                                        = "secure_cells.session.thread.decision.escalate"
	secureCellSessionThreadDecisionOutcomeAction                                         = "secure_cells.session.thread.decision.publish_outcome"
	secureCellSessionThreadDecisionContainAction                                         = "secure_cells.session.thread.decision.contain_outputs"
	secureCellSessionThreadDecisionQuarantineAction                                      = "secure_cells.session.thread.decision.quarantine"
	secureCellSessionThreadDecisionReleaseAction                                         = "secure_cells.session.thread.decision.release_outputs"
	secureCellSessionThreadDecisionResumeAction                                          = "secure_cells.session.thread.decision.resume"
	secureCellSessionThreadDecisionCloseAction                                           = "secure_cells.session.thread.decision.close"
	secureCellSessionShareAction                                                         = "secure_cells.session.share"
	secureCellSessionExchangeAction                                                      = "secure_cells.session.exchange"
	secureCellSessionCloseAction                                                         = "secure_cells.session.close"
	secureCellSessionPauseAction                                                         = "secure_cells.session.pause"
	secureCellSessionResumeAction                                                        = "secure_cells.session.resume"
	secureCellSessionQuarantineAction                                                    = "secure_cells.session.quarantine"
	secureCellSessionThreadCloseAction                                                   = "secure_cells.session.thread.close"
	secureCellSessionThreadResumeAction                                                  = "secure_cells.session.thread.resume"
	secureCellSessionThreadQuarantineAction                                              = "secure_cells.session.thread.quarantine"
	secureCellSessionMemberAdmitAction                                                   = "secure_cells.session.member.admit"
	secureCellSessionMemberRemoveAction                                                  = "secure_cells.session.member.remove"
	secureCellMemberAdmitAction                                                          = "secure_cells.member.admit"
	secureCellFederationInviteAction                                                     = "secure_cells.federation.invite"
	secureCellFederationAcceptAction                                                     = "secure_cells.federation.accept"
	secureCellFederationRevokeAction                                                     = "secure_cells.federation.revoke"
	secureCellFederationCounterproposeAction                                             = "secure_cells.federation.counterproposal.submit"
	secureCellFederationCounterproposalEscalateAction                                    = "secure_cells.federation.counterproposal.escalate"
	secureCellFederationCounterproposalApproveAction                                     = "secure_cells.federation.counterproposal.approve"
	secureCellFederationCounterproposalRejectAction                                      = "secure_cells.federation.counterproposal.reject"
	secureCellFederationContractRenewAction                                              = "secure_cells.federation.contract.renew"
	secureCellFederationContractSuspendAction                                            = "secure_cells.federation.contract.suspend"
	secureCellFederationContractResumeAction                                             = "secure_cells.federation.contract.resume"
	secureCellFederationContractRevokeAction                                             = "secure_cells.federation.contract.revoke"
	secureCellFederationAssuranceIntakeAction                                            = "secure_cells.federation.assurance.intake"
	secureCellFederationIncidentPublishAction                                            = "secure_cells.federation.incident.publish"
	secureCellFederationIncidentResolveAction                                            = "secure_cells.federation.incident.resolve"
	secureCellFederationIncidentIntakeAction                                             = "secure_cells.federation.incident.intake"
	secureCellFederationIncidentContainAction                                            = "secure_cells.federation.incident.contain_artifacts"
	secureCellFederationIncidentResponseAcknowledgeAction                                = "secure_cells.federation.incident.response.acknowledge"
	secureCellFederationIncidentResponseEscalateAction                                   = "secure_cells.federation.incident.response.escalate"
	secureCellFederationIncidentRemediationAttestAction                                  = "secure_cells.federation.incident.response.attest_remediation"
	secureCellFederationIncidentRemediationVerifyAction                                  = "secure_cells.federation.incident.response.verify_remediation"
	secureCellFederationIncidentClosureAttestAction                                      = "secure_cells.federation.incident.response.attest_closure"
	secureCellFederationIncidentResponseDisputeAction                                    = "secure_cells.federation.incident.response.dispute"
	secureCellFederationIncidentDirectiveIssueAction                                     = "secure_cells.federation.incident.response.directive.issue"
	secureCellFederationIncidentDirectiveAcknowledgeAction                               = "secure_cells.federation.incident.directive.acknowledge"
	secureCellFederationIncidentDirectiveCompleteAction                                  = "secure_cells.federation.incident.directive.complete"
	secureCellFederationIncidentDirectiveVerifyAction                                    = "secure_cells.federation.incident.directive.verify"
	secureCellFederationIncidentDirectiveExtensionRequestAction                          = "secure_cells.federation.incident.directive.extension.request"
	secureCellFederationIncidentDirectiveExtensionApproveAction                          = "secure_cells.federation.incident.directive.extension.approve"
	secureCellFederationIncidentDirectiveExtensionRejectAction                           = "secure_cells.federation.incident.directive.extension.reject"
	secureCellFederationIncidentDirectiveExtensionDisputeAction                          = "secure_cells.federation.incident.directive.extension.dispute"
	secureCellFederationIncidentDirectiveExtensionResolveAction                          = "secure_cells.federation.incident.directive.extension.resolve"
	secureCellFederationIncidentDirectiveExtensionDelegateReviewAction                   = "secure_cells.federation.incident.directive.extension.delegate_review"
	secureCellFederationIncidentDirectiveExtensionDelegateResolutionAction               = "secure_cells.federation.incident.directive.extension.delegate_resolution"
	secureCellFederationIncidentDirectiveExtensionAppealAction                           = "secure_cells.federation.incident.directive.extension.appeal"
	secureCellFederationIncidentDirectiveExtensionAppealRuleAction                       = "secure_cells.federation.incident.directive.extension.appeal.rule"
	secureCellFederationIncidentDirectiveExtensionAppealDelegateReviewAction             = "secure_cells.federation.incident.directive.extension.appeal.delegate_review"
	secureCellFederationIncidentDirectiveExtensionAppealRecuseAction                     = "secure_cells.federation.incident.directive.extension.appeal.recuse_review"
	secureCellFederationIncidentDirectiveExtensionAppealRehearAction                     = "secure_cells.federation.incident.directive.extension.appeal.rehear"
	secureCellFederationIncidentDirectiveExtensionAppealIntakeAction                     = "secure_cells.federation.incident.directive.extension.appeal.intake"
	secureCellFederationIncidentDirectiveExtensionAppealAcknowledgeAction                = "secure_cells.federation.incident.directive.extension.appeal.acknowledge_enforcement"
	secureCellFederationIncidentDirectiveExtensionAppealReconcileAckAction               = "secure_cells.federation.incident.directive.extension.appeal.reconciliation.acknowledge"
	secureCellFederationIncidentDirectiveExtensionAppealReconcileDisputeAction           = "secure_cells.federation.incident.directive.extension.appeal.reconciliation.dispute"
	secureCellFederationIncidentDirectiveExtensionAppealReconcileResolveAction           = "secure_cells.federation.incident.directive.extension.appeal.reconciliation.resolve"
	secureCellFederationIncidentDirectiveExtensionAppealReconcileChallengeAction         = "secure_cells.federation.incident.directive.extension.appeal.reconciliation.challenge"
	secureCellFederationIncidentDirectiveExtensionAppealReconcileChallengeDelegateAction = "secure_cells.federation.incident.directive.extension.appeal.reconciliation.delegate_review"
	secureCellFederationIncidentDirectiveExtensionAppealReconcileRuleAction              = "secure_cells.federation.incident.directive.extension.appeal.reconciliation.rule"
	secureCellFederationIncidentDirectiveExtensionAppealReconcileCounterpartyAckAction   = "secure_cells.federation.incident.directive.extension.appeal.reconciliation.acknowledge_dispute"
	secureCellFederationIncidentDirectiveExtensionAppealReconcileCorrectionAttestAction  = "secure_cells.federation.incident.directive.extension.appeal.reconciliation.attest_correction"
	secureCellFederationIncidentDirectiveExtensionAppealReconcileResolutionAttestAction  = "secure_cells.federation.incident.directive.extension.appeal.reconciliation.attest_resolution"
	secureCellFederationIncidentDirectiveExtensionAppealReconcileEscalateAction          = "secure_cells.federation.incident.directive.extension.appeal.reconciliation.escalate"
	secureCellFederationIncidentReportPlanAction                                         = "secure_cells.federation.incident.response.report.plan"
	secureCellFederationIncidentReportIntakeAction                                       = "secure_cells.federation.incident.report.intake"
	secureCellFederationIncidentReportAmendAction                                        = "secure_cells.federation.incident.report.amend"
	secureCellFederationIncidentReportSubmitAction                                       = "secure_cells.federation.incident.report.submit"
	secureCellFederationIncidentReportAcknowledgeAction                                  = "secure_cells.federation.incident.report.acknowledge"
	secureCellFederationIncidentReportAmendmentIntakeAction                              = "secure_cells.federation.incident.report.amendment.intake"
	secureCellFederationIncidentReportAmendmentSubmitAction                              = "secure_cells.federation.incident.report.amendment.submit"
	secureCellFederationIncidentReportAmendmentAckAction                                 = "secure_cells.federation.incident.report.amendment.acknowledge"
	secureCellFederationIncidentReportReconcileAckAction                                 = "secure_cells.federation.incident.report.reconciliation.acknowledge"
	secureCellFederationIncidentReportReconcileDisputeAction                             = "secure_cells.federation.incident.report.reconciliation.dispute"
	secureCellFederationIncidentReportReconcileResolveAction                             = "secure_cells.federation.incident.report.reconciliation.resolve"
	secureCellFederationIncidentReportAmendmentReconcileAckAction                        = "secure_cells.federation.incident.report.amendment.reconciliation.acknowledge"
	secureCellFederationIncidentReportAmendmentReconcileDisputeAction                    = "secure_cells.federation.incident.report.amendment.reconciliation.dispute"
	secureCellFederationIncidentReportAmendmentReconcileResolveAction                    = "secure_cells.federation.incident.report.amendment.reconciliation.resolve"
	secureCellFederationIncidentReportAmendmentReconcileCounterpartyAckAction            = "secure_cells.federation.incident.report.amendment.reconciliation.counterparty_acknowledge"
	secureCellFederationIncidentReportAmendmentReconcileCorrectionAttestAction           = "secure_cells.federation.incident.report.amendment.reconciliation.attest_correction"
	secureCellFederationIncidentReportAmendmentReconcileResolutionAttestAction           = "secure_cells.federation.incident.report.amendment.reconciliation.attest_resolution"
	secureCellFederationIncidentReportAmendmentReconcileEscalateAction                   = "secure_cells.federation.incident.report.amendment.reconciliation.escalate"
	secureCellMemberReleaseAction                                                        = "secure_cells.member.release"
	secureCellMemberQuarantineAction                                                     = "secure_cells.member.quarantine"
	secureCellMemberRevokeAction                                                         = "secure_cells.member.revoke"
	secureCellQuarantineExpireAction                                                     = "secure_cells.quarantine.expire"
	secureCellPauseAction                                                                = "secure_cells.pause"
	secureCellResumeAction                                                               = "secure_cells.resume"
	secureCellTerminateAction                                                            = "secure_cells.terminate"
)

// SecureCellSessionStatus tracks one governed collaboration session inside a
// live secure cell.
type SecureCellSessionStatus string

const (
	SecureCellSessionStatusActive      SecureCellSessionStatus = "active"
	SecureCellSessionStatusPaused      SecureCellSessionStatus = "paused"
	SecureCellSessionStatusQuarantined SecureCellSessionStatus = "quarantined"
	SecureCellSessionStatusClosed      SecureCellSessionStatus = "closed"
)

// SecureCellThreadStatus tracks a collaboration thread or output stream inside
// one governed session.
type SecureCellThreadStatus string

const (
	SecureCellThreadStatusActive      SecureCellThreadStatus = "active"
	SecureCellThreadStatusQuarantined SecureCellThreadStatus = "quarantined"
	SecureCellThreadStatusClosed      SecureCellThreadStatus = "closed"
)

// SecureCellThreadDecisionStatus tracks one governed decision object inside a
// collaboration thread.
type SecureCellThreadDecisionStatus string

const (
	SecureCellThreadDecisionStatusOpen         SecureCellThreadDecisionStatus = "open"
	SecureCellThreadDecisionStatusApproved     SecureCellThreadDecisionStatus = "approved"
	SecureCellThreadDecisionStatusQuorumFailed SecureCellThreadDecisionStatus = "quorum_failed"
	SecureCellThreadDecisionStatusQuarantined  SecureCellThreadDecisionStatus = "quarantined"
	SecureCellThreadDecisionStatusClosed       SecureCellThreadDecisionStatus = "closed"
)

// SecureCellArtifactContainmentStatus tracks containment posture for outputs
// and exchanges bound to a governed decision.
type SecureCellArtifactContainmentStatus string

const (
	SecureCellArtifactContainmentStatusActive    SecureCellArtifactContainmentStatus = "active"
	SecureCellArtifactContainmentStatusContained SecureCellArtifactContainmentStatus = "contained"
	SecureCellArtifactContainmentStatusReleased  SecureCellArtifactContainmentStatus = "released"
)

// SecureCellThreadDecisionVoteChoice tracks one approval vote outcome.
type SecureCellThreadDecisionVoteChoice string

const (
	SecureCellThreadDecisionVoteChoiceApprove SecureCellThreadDecisionVoteChoice = "approve"
	SecureCellThreadDecisionVoteChoiceReject  SecureCellThreadDecisionVoteChoice = "reject"
	SecureCellThreadDecisionVoteChoiceAbstain SecureCellThreadDecisionVoteChoice = "abstain"
)

// SecureCellThreadDecisionDelegationMode tracks whether a decision actor was
// delegated or escalated into a governed decision flow.
type SecureCellThreadDecisionDelegationMode string

const (
	SecureCellThreadDecisionDelegationModeDelegate SecureCellThreadDecisionDelegationMode = "delegate"
	SecureCellThreadDecisionDelegationModeEscalate SecureCellThreadDecisionDelegationMode = "escalate"
)

// SecureCellSealer creates execution seals for secure cells.
type SecureCellSealer interface {
	CreateSeal(ctx context.Context, req sdk.SealRequest) (*sdk.SealResponse, error)
}

// SecureCellPackageSigner signs a portable control-ledger package.
type SecureCellPackageSigner func(ctx context.Context, pkg *evidence.PortableControlLedgerPackage) error

// SecureCellFederationAssuranceBundleSigner signs a portable federation
// assurance bundle for reciprocal cross-organization exchange.
type SecureCellFederationAssuranceBundleSigner func(ctx context.Context, bundle *SecureCellFederationAssuranceBundle) error

// SecureCellFederationIncidentBulletinSigner signs a portable federation
// incident bulletin for reciprocal cross-organization exchange.
type SecureCellFederationIncidentBulletinSigner func(ctx context.Context, bulletin *SecureCellFederationIncidentBulletin) error

// SecureCellFederationIncidentResponseBundleSigner signs a portable
// federation incident response bundle for auditor exchange.
type SecureCellFederationIncidentResponseBundleSigner func(ctx context.Context, bundle *SecureCellFederationIncidentResponseBundle) error

// SecureCellFederationIncidentDirectiveBundleSigner signs a portable
// federation incident directive bundle for auditor and operator exchange.
type SecureCellFederationIncidentDirectiveBundleSigner func(ctx context.Context, bundle *SecureCellFederationIncidentDirectiveBundle) error

// SecureCellFederationIncidentDirectiveExtensionAppealBundleSigner signs a
// portable directive-exception appeal bundle for auditor and operator exchange.
type SecureCellFederationIncidentDirectiveExtensionAppealBundleSigner func(ctx context.Context, bundle *SecureCellFederationIncidentDirectiveExtensionAppealBundle) error

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleSigner
// signs a portable bilateral directive-exception appeal reconciliation bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleSigner func(ctx context.Context, bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle) error

// SecureCellFederationIncidentReportBundleSigner signs a portable
// federation incident report bundle for auditor and regulator exchange.
type SecureCellFederationIncidentReportBundleSigner func(ctx context.Context, bundle *SecureCellFederationIncidentReportBundle) error

// SecureCellFederationIncidentReportAmendmentBundleSigner signs a portable
// federation incident report amendment bundle for auditor and regulator exchange.
type SecureCellFederationIncidentReportAmendmentBundleSigner func(ctx context.Context, bundle *SecureCellFederationIncidentReportAmendmentBundle) error

// SecureCellFederationIncidentReportReconciliationBundleSigner signs a
// portable bilateral incident-report reconciliation bundle.
type SecureCellFederationIncidentReportReconciliationBundleSigner func(ctx context.Context, bundle *SecureCellFederationIncidentReportReconciliationBundle) error

// SecureCellFederationIncidentReportAmendmentReconciliationBundleSigner signs a
// portable bilateral incident-report amendment reconciliation bundle.
type SecureCellFederationIncidentReportAmendmentReconciliationBundleSigner func(ctx context.Context, bundle *SecureCellFederationIncidentReportAmendmentReconciliationBundle) error

// SecureCellFederationIncidentCasePackSigner signs a portable bilateral
// incident case pack for auditor and operator exchange.
type SecureCellFederationIncidentCasePackSigner func(ctx context.Context, pack *SecureCellFederationIncidentCasePack) error

// SecureCellPackageAnchorer anchors a portable package into external audit or governance state.
type SecureCellPackageAnchorer func(ctx context.Context, pkg *evidence.PortableControlLedgerPackage) error

// SecureCellEventPublisher publishes finalized lifecycle events after the
// sealed evidence package has been regenerated successfully.
type SecureCellEventPublisher func(ctx context.Context, event SecureCellLifecycleEvent)

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

// SecureCellSession is the explicit collaboration-room model inside a secure
// cell. Sessions are policy-gated and portable through the evidence chain.
type SecureCellSession struct {
	ID               string                  `json:"id"`
	Name             string                  `json:"name"`
	Purpose          string                  `json:"purpose,omitempty"`
	Status           SecureCellSessionStatus `json:"status"`
	PausedFromStatus SecureCellSessionStatus `json:"paused_from_status,omitempty"`
	ParticipantDIDs  []string                `json:"participant_dids,omitempty"`
	DataClasses      []string                `json:"data_classes,omitempty"`
	StartedBy        string                  `json:"started_by,omitempty"`
	ClosedBy         string                  `json:"closed_by,omitempty"`
	SharedOutputIDs  []string                `json:"shared_output_ids,omitempty"`
	ExchangeIDs      []string                `json:"exchange_ids,omitempty"`
	OpenedAt         time.Time               `json:"opened_at"`
	QuarantinedAt    *time.Time              `json:"quarantined_at,omitempty"`
	ClosedAt         *time.Time              `json:"closed_at,omitempty"`
	UpdatedAt        time.Time               `json:"updated_at"`
	ContainedBy      string                  `json:"contained_by,omitempty"`
	Metadata         map[string]string       `json:"metadata,omitempty"`
}

// SecureCellSessionThread is one governed collaboration stream inside a
// session. Threads allow targeted containment without freezing the full room.
type SecureCellSessionThread struct {
	ID              string                 `json:"id"`
	SessionID       string                 `json:"session_id"`
	Name            string                 `json:"name"`
	Purpose         string                 `json:"purpose,omitempty"`
	Status          SecureCellThreadStatus `json:"status"`
	ParticipantDIDs []string               `json:"participant_dids,omitempty"`
	DataClasses     []string               `json:"data_classes,omitempty"`
	StartedBy       string                 `json:"started_by,omitempty"`
	ClosedBy        string                 `json:"closed_by,omitempty"`
	DecisionIDs     []string               `json:"decision_ids,omitempty"`
	ExchangeIDs     []string               `json:"exchange_ids,omitempty"`
	OpenedAt        time.Time              `json:"opened_at"`
	QuarantinedAt   *time.Time             `json:"quarantined_at,omitempty"`
	ClosedAt        *time.Time             `json:"closed_at,omitempty"`
	UpdatedAt       time.Time              `json:"updated_at"`
	ContainedBy     string                 `json:"contained_by,omitempty"`
	Metadata        map[string]string      `json:"metadata,omitempty"`
}

// SecureCellThreadDecision is one evidence-bearing decision object inside a
// governed collaboration thread.
type SecureCellThreadDecisionVote struct {
	ID                string                             `json:"id"`
	DecisionID        string                             `json:"decision_id"`
	ActorDID          string                             `json:"actor_did"`
	ActorRole         string                             `json:"actor_role,omitempty"`
	Choice            SecureCellThreadDecisionVoteChoice `json:"choice"`
	Reason            string                             `json:"reason,omitempty"`
	PolicyReceiptID   string                             `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string                             `json:"policy_receipt_hash,omitempty"`
	SealID            string                             `json:"seal_id,omitempty"`
	TraceLinkID       string                             `json:"trace_link_id,omitempty"`
	CreatedAt         time.Time                          `json:"created_at"`
	Metadata          map[string]string                  `json:"metadata,omitempty"`
}

// SecureCellThreadDecisionComment is one evidence-bearing collaboration note
// attached to a governed thread decision.
type SecureCellThreadDecisionComment struct {
	ID                string            `json:"id"`
	DecisionID        string            `json:"decision_id"`
	ActorDID          string            `json:"actor_did"`
	ActorRole         string            `json:"actor_role,omitempty"`
	Comment           string            `json:"comment"`
	Reason            string            `json:"reason,omitempty"`
	PolicyReceiptID   string            `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string            `json:"policy_receipt_hash,omitempty"`
	SealID            string            `json:"seal_id,omitempty"`
	TraceLinkID       string            `json:"trace_link_id,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// SecureCellThreadDecisionDelegation is one evidence-bearing decision routing
// action that broadens who may participate in a governed decision flow.
type SecureCellThreadDecisionDelegation struct {
	ID                string                                 `json:"id"`
	DecisionID        string                                 `json:"decision_id"`
	FromActorDID      string                                 `json:"from_actor_did"`
	FromActorRole     string                                 `json:"from_actor_role,omitempty"`
	ToActorDID        string                                 `json:"to_actor_did"`
	ToActorRole       string                                 `json:"to_actor_role,omitempty"`
	Mode              SecureCellThreadDecisionDelegationMode `json:"mode"`
	Reason            string                                 `json:"reason,omitempty"`
	PolicyReceiptID   string                                 `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string                                 `json:"policy_receipt_hash,omitempty"`
	SealID            string                                 `json:"seal_id,omitempty"`
	TraceLinkID       string                                 `json:"trace_link_id,omitempty"`
	CreatedAt         time.Time                              `json:"created_at"`
	Metadata          map[string]string                      `json:"metadata,omitempty"`
}

// SecureCellDecisionEscalationTier defines one timed escalation stage for a
// governed decision.
type SecureCellDecisionEscalationTier struct {
	TierID    string                                 `json:"tier_id,omitempty"`
	TargetDID string                                 `json:"target_did,omitempty"`
	Mode      SecureCellThreadDecisionDelegationMode `json:"mode,omitempty"`
	DueAt     *time.Time                             `json:"due_at,omitempty"`
	Reason    string                                 `json:"reason,omitempty"`
	Metadata  map[string]string                      `json:"metadata,omitempty"`
}

// SecureCellThreadDecisionOutcome is one portable outcome bundle emitted from
// a governed decision after deliberation.
type SecureCellThreadDecisionOutcome struct {
	ID                 string            `json:"id"`
	DecisionID         string            `json:"decision_id"`
	SessionID          string            `json:"session_id"`
	ThreadID           string            `json:"thread_id"`
	Title              string            `json:"title"`
	Summary            string            `json:"summary,omitempty"`
	Classification     string            `json:"classification,omitempty"`
	OutcomeType        string            `json:"outcome_type,omitempty"`
	PublishedBy        string            `json:"published_by,omitempty"`
	PublishedByRole    string            `json:"published_by_role,omitempty"`
	RelatedExchangeIDs []string          `json:"related_exchange_ids,omitempty"`
	RelatedOutputIDs   []string          `json:"related_output_ids,omitempty"`
	IntegrityHash      string            `json:"integrity_hash"`
	PolicyReceiptID    string            `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash  string            `json:"policy_receipt_hash,omitempty"`
	SealID             string            `json:"seal_id,omitempty"`
	TraceLinkID        string            `json:"trace_link_id,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

type SecureCellThreadDecision struct {
	ID                    string                               `json:"id"`
	SessionID             string                               `json:"session_id"`
	ThreadID              string                               `json:"thread_id"`
	Title                 string                               `json:"title"`
	Summary               string                               `json:"summary,omitempty"`
	Classification        string                               `json:"classification,omitempty"`
	GovernanceTemplate    string                               `json:"governance_template,omitempty"`
	SLATemplate           string                               `json:"sla_template,omitempty"`
	SectorPolicyPack      string                               `json:"sector_policy_pack,omitempty"`
	Status                SecureCellThreadDecisionStatus       `json:"status"`
	QuarantinedFromStatus SecureCellThreadDecisionStatus       `json:"quarantined_from_status,omitempty"`
	ApprovalThreshold     int                                  `json:"approval_threshold,omitempty"`
	EligibleApproverDIDs  []string                             `json:"eligible_approver_dids,omitempty"`
	RequiredApproverRoles []string                             `json:"required_approver_roles,omitempty"`
	AllowedVoteChoices    []SecureCellThreadDecisionVoteChoice `json:"allowed_vote_choices,omitempty"`
	RejectorRoles         []string                             `json:"rejector_roles,omitempty"`
	AbstainerRoles        []string                             `json:"abstainer_roles,omitempty"`
	ReopenRoles           []string                             `json:"reopen_roles,omitempty"`
	EscalationLadder      []SecureCellDecisionEscalationTier   `json:"escalation_ladder,omitempty"`
	AutoEscalateToDID     string                               `json:"auto_escalate_to_did,omitempty"`
	ApprovalVotes         []SecureCellThreadDecisionVote       `json:"approval_votes,omitempty"`
	Comments              []SecureCellThreadDecisionComment    `json:"comments,omitempty"`
	Delegations           []SecureCellThreadDecisionDelegation `json:"delegations,omitempty"`
	OutcomeIDs            []string                             `json:"outcome_ids,omitempty"`
	ProposedBy            string                               `json:"proposed_by,omitempty"`
	ApprovedBy            string                               `json:"approved_by,omitempty"`
	QuorumFailedBy        string                               `json:"quorum_failed_by,omitempty"`
	ClosedBy              string                               `json:"closed_by,omitempty"`
	RelatedExchangeIDs    []string                             `json:"related_exchange_ids,omitempty"`
	RelatedOutputIDs      []string                             `json:"related_output_ids,omitempty"`
	ProposedAt            time.Time                            `json:"proposed_at"`
	EscalationDueAt       *time.Time                           `json:"escalation_due_at,omitempty"`
	ResolutionDueAt       *time.Time                           `json:"resolution_due_at,omitempty"`
	ApprovedAt            *time.Time                           `json:"approved_at,omitempty"`
	QuorumFailedAt        *time.Time                           `json:"quorum_failed_at,omitempty"`
	QuarantinedAt         *time.Time                           `json:"quarantined_at,omitempty"`
	ClosedAt              *time.Time                           `json:"closed_at,omitempty"`
	UpdatedAt             time.Time                            `json:"updated_at"`
	ContainedBy           string                               `json:"contained_by,omitempty"`
	Metadata              map[string]string                    `json:"metadata,omitempty"`
}

// SecureCellSessionExchange captures one message or exchange artifact inside a
// governed collaboration session.
type SecureCellSessionExchange struct {
	ID                     string                              `json:"id"`
	SessionID              string                              `json:"session_id"`
	ThreadID               string                              `json:"thread_id,omitempty"`
	Name                   string                              `json:"name"`
	ExchangeType           string                              `json:"exchange_type,omitempty"`
	Classification         string                              `json:"classification,omitempty"`
	Resource               string                              `json:"resource,omitempty"`
	Summary                string                              `json:"summary,omitempty"`
	SentBy                 string                              `json:"sent_by,omitempty"`
	Recipients             []string                            `json:"recipients,omitempty"`
	FederationContractIDs  []string                            `json:"federation_contract_ids,omitempty"`
	FederationOrgIDs       []string                            `json:"federation_org_ids,omitempty"`
	IntegrityHash          string                              `json:"integrity_hash"`
	PolicyReceiptID        string                              `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash      string                              `json:"policy_receipt_hash,omitempty"`
	SealID                 string                              `json:"seal_id,omitempty"`
	TraceLinkID            string                              `json:"trace_link_id,omitempty"`
	ContainmentStatus      SecureCellArtifactContainmentStatus `json:"containment_status,omitempty"`
	ContainmentDecisionID  string                              `json:"containment_decision_id,omitempty"`
	ContainmentSourceType  string                              `json:"containment_source_type,omitempty"`
	ContainmentSourceID    string                              `json:"containment_source_id,omitempty"`
	ContainmentReceiptID   string                              `json:"containment_receipt_id,omitempty"`
	ContainmentReceiptHash string                              `json:"containment_receipt_hash,omitempty"`
	ContainmentSealID      string                              `json:"containment_seal_id,omitempty"`
	ContainmentTraceLinkID string                              `json:"containment_trace_link_id,omitempty"`
	ContainedBy            string                              `json:"contained_by,omitempty"`
	ContainedAt            *time.Time                          `json:"contained_at,omitempty"`
	ReleasedBy             string                              `json:"released_by,omitempty"`
	ReleasedAt             *time.Time                          `json:"released_at,omitempty"`
	ChainOfCustody         []evidence.CustodyEntry             `json:"chain_of_custody,omitempty"`
	CreatedAt              time.Time                           `json:"created_at"`
	Metadata               map[string]string                   `json:"metadata,omitempty"`
}

// SecureCellSharedOutput captures one policy-bound data exchange inside a
// session, including provenance-bearing custody details.
type SecureCellSharedOutput struct {
	ID                     string                              `json:"id"`
	SessionID              string                              `json:"session_id"`
	Name                   string                              `json:"name"`
	ArtifactType           string                              `json:"artifact_type,omitempty"`
	Classification         string                              `json:"classification,omitempty"`
	Resource               string                              `json:"resource,omitempty"`
	Summary                string                              `json:"summary,omitempty"`
	ProducedBy             string                              `json:"produced_by,omitempty"`
	SharedWith             []string                            `json:"shared_with,omitempty"`
	FederationContractIDs  []string                            `json:"federation_contract_ids,omitempty"`
	FederationOrgIDs       []string                            `json:"federation_org_ids,omitempty"`
	IntegrityHash          string                              `json:"integrity_hash"`
	PolicyReceiptID        string                              `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash      string                              `json:"policy_receipt_hash,omitempty"`
	SealID                 string                              `json:"seal_id,omitempty"`
	TraceLinkID            string                              `json:"trace_link_id,omitempty"`
	ContainmentStatus      SecureCellArtifactContainmentStatus `json:"containment_status,omitempty"`
	ContainmentDecisionID  string                              `json:"containment_decision_id,omitempty"`
	ContainmentSourceType  string                              `json:"containment_source_type,omitempty"`
	ContainmentSourceID    string                              `json:"containment_source_id,omitempty"`
	ContainmentReceiptID   string                              `json:"containment_receipt_id,omitempty"`
	ContainmentReceiptHash string                              `json:"containment_receipt_hash,omitempty"`
	ContainmentSealID      string                              `json:"containment_seal_id,omitempty"`
	ContainmentTraceLinkID string                              `json:"containment_trace_link_id,omitempty"`
	ContainedBy            string                              `json:"contained_by,omitempty"`
	ContainedAt            *time.Time                          `json:"contained_at,omitempty"`
	ReleasedBy             string                              `json:"released_by,omitempty"`
	ReleasedAt             *time.Time                          `json:"released_at,omitempty"`
	ChainOfCustody         []evidence.CustodyEntry             `json:"chain_of_custody,omitempty"`
	CreatedAt              time.Time                           `json:"created_at"`
	Metadata               map[string]string                   `json:"metadata,omitempty"`
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
	CellID                                                  string                                                                     `json:"cell_id"`
	Name                                                    string                                                                     `json:"name"`
	Purpose                                                 string                                                                     `json:"purpose"`
	Status                                                  SecureCellStatus                                                           `json:"status"`
	PausedFromStatus                                        SecureCellStatus                                                           `json:"paused_from_status,omitempty"`
	Policy                                                  SecureCellPolicy                                                           `json:"policy"`
	Participants                                            []SecureCellParticipantState                                               `json:"participants,omitempty"`
	FederationOrganizations                                 []SecureCellFederationOrganization                                         `json:"federation_organizations,omitempty"`
	FederationInvitations                                   []SecureCellFederationInvitation                                           `json:"federation_invitations,omitempty"`
	FederationCounterproposals                              []SecureCellFederationCounterproposal                                      `json:"federation_counterproposals,omitempty"`
	FederationContracts                                     []SecureCellFederationContract                                             `json:"federation_contracts,omitempty"`
	FederationCounterpartyAssurance                         []SecureCellFederationCounterpartyAssuranceSnapshot                        `json:"federation_counterparty_assurance,omitempty"`
	FederationIncidents                                     []SecureCellFederationIncident                                             `json:"federation_incidents,omitempty"`
	FederationCounterpartyIncidents                         []SecureCellFederationCounterpartyIncidentSnapshot                         `json:"federation_counterparty_incidents,omitempty"`
	FederationCounterpartyIncidentReports                   []SecureCellFederationCounterpartyIncidentReportSnapshot                   `json:"federation_counterparty_incident_reports,omitempty"`
	FederationCounterpartyIncidentReportAmendments          []SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot          `json:"federation_counterparty_incident_report_amendments,omitempty"`
	FederationCounterpartyIncidentDirectiveExtensionAppeals []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSnapshot `json:"federation_counterparty_incident_directive_extension_appeals,omitempty"`
	FederationIncidentResponses                             []SecureCellFederationIncidentResponse                                     `json:"federation_incident_responses,omitempty"`
	Sessions                                                []SecureCellSession                                                        `json:"sessions,omitempty"`
	Threads                                                 []SecureCellSessionThread                                                  `json:"threads,omitempty"`
	Decisions                                               []SecureCellThreadDecision                                                 `json:"decisions,omitempty"`
	DecisionOutcomes                                        []SecureCellThreadDecisionOutcome                                          `json:"decision_outcomes,omitempty"`
	SharedOutputs                                           []SecureCellSharedOutput                                                   `json:"shared_outputs,omitempty"`
	SessionExchanges                                        []SecureCellSessionExchange                                                `json:"session_exchanges,omitempty"`
	CreationReceipt                                         *policy.SignedPolicyReceipt                                                `json:"creation_receipt,omitempty"`
	ActivationReceipt                                       *policy.SignedPolicyReceipt                                                `json:"activation_receipt,omitempty"`
	ReceiptChain                                            *policy.PolicyReceiptChain                                                 `json:"receipt_chain,omitempty"`
	ConfidentialExecution                                   *confidential.VerificationSummary                                          `json:"confidential_execution,omitempty"`
	ExecutionAttestations                                   []evidence.Attestation                                                     `json:"execution_attestations,omitempty"`
	ExecutionSeal                                           *evidence.Seal                                                             `json:"execution_seal,omitempty"`
	ControlLedger                                           *evidence.ControlLedger                                                    `json:"control_ledger,omitempty"`
	PortablePackage                                         *evidence.PortableControlLedgerPackage                                     `json:"portable_package,omitempty"`
	Transitions                                             []SecureCellTransition                                                     `json:"transitions,omitempty"`
	RejectionReason                                         string                                                                     `json:"rejection_reason,omitempty"`
	TerminatedAt                                            *time.Time                                                                 `json:"terminated_at,omitempty"`
	CreatedAt                                               time.Time                                                                  `json:"created_at"`
	UpdatedAt                                               time.Time                                                                  `json:"updated_at"`
}

// SecureCellTransition captures one evidence-bearing lifecycle mutation after
// the cell is provisioned.
type SecureCellTransition struct {
	ID                      string                         `json:"id"`
	Action                  string                         `json:"action"`
	Actor                   string                         `json:"actor"`
	TargetType              string                         `json:"target_type,omitempty"`
	TargetDID               string                         `json:"target_did,omitempty"`
	SessionID               string                         `json:"session_id,omitempty"`
	ThreadID                string                         `json:"thread_id,omitempty"`
	DecisionID              string                         `json:"decision_id,omitempty"`
	SharedOutputID          string                         `json:"shared_output_id,omitempty"`
	SessionExchangeID       string                         `json:"session_exchange_id,omitempty"`
	SessionStatusBefore     SecureCellSessionStatus        `json:"session_status_before,omitempty"`
	SessionStatusAfter      SecureCellSessionStatus        `json:"session_status_after,omitempty"`
	ThreadStatusBefore      SecureCellThreadStatus         `json:"thread_status_before,omitempty"`
	ThreadStatusAfter       SecureCellThreadStatus         `json:"thread_status_after,omitempty"`
	DecisionStatusBefore    SecureCellThreadDecisionStatus `json:"decision_status_before,omitempty"`
	DecisionStatusAfter     SecureCellThreadDecisionStatus `json:"decision_status_after,omitempty"`
	CellStatusBefore        SecureCellStatus               `json:"cell_status_before,omitempty"`
	CellStatusAfter         SecureCellStatus               `json:"cell_status_after,omitempty"`
	ParticipantStatusBefore SecureCellParticipantStatus    `json:"participant_status_before,omitempty"`
	ParticipantStatusAfter  SecureCellParticipantStatus    `json:"participant_status_after,omitempty"`
	NegotiationID           string                         `json:"negotiation_id,omitempty"`
	CredentialID            string                         `json:"credential_id,omitempty"`
	PolicyReceipt           *policy.SignedPolicyReceipt    `json:"policy_receipt,omitempty"`
	ExecutionSeal           *evidence.Seal                 `json:"execution_seal,omitempty"`
	TraceLink               *evidence.TraceLink            `json:"trace_link,omitempty"`
	Reason                  string                         `json:"reason,omitempty"`
	Metadata                map[string]string              `json:"metadata,omitempty"`
	OccurredAt              time.Time                      `json:"occurred_at"`
}

// SecureCellLifecycleEvent is the canonical event payload emitted after a
// secure-cell lifecycle mutation has been sealed and packaged successfully.
type SecureCellLifecycleEvent struct {
	EventID                     string                         `json:"event_id"`
	CellID                      string                         `json:"cell_id"`
	Name                        string                         `json:"name"`
	Purpose                     string                         `json:"purpose"`
	Jurisdiction                string                         `json:"jurisdiction,omitempty"`
	Action                      string                         `json:"action"`
	Actor                       string                         `json:"actor"`
	TargetType                  string                         `json:"target_type,omitempty"`
	TargetDID                   string                         `json:"target_did,omitempty"`
	SessionID                   string                         `json:"session_id,omitempty"`
	ThreadID                    string                         `json:"thread_id,omitempty"`
	DecisionID                  string                         `json:"decision_id,omitempty"`
	SharedOutputID              string                         `json:"shared_output_id,omitempty"`
	SessionExchangeID           string                         `json:"session_exchange_id,omitempty"`
	SessionStatusBefore         SecureCellSessionStatus        `json:"session_status_before,omitempty"`
	SessionStatusAfter          SecureCellSessionStatus        `json:"session_status_after,omitempty"`
	ThreadStatusBefore          SecureCellThreadStatus         `json:"thread_status_before,omitempty"`
	ThreadStatusAfter           SecureCellThreadStatus         `json:"thread_status_after,omitempty"`
	DecisionStatusBefore        SecureCellThreadDecisionStatus `json:"decision_status_before,omitempty"`
	DecisionStatusAfter         SecureCellThreadDecisionStatus `json:"decision_status_after,omitempty"`
	CellStatus                  SecureCellStatus               `json:"cell_status"`
	CellStatusBefore            SecureCellStatus               `json:"cell_status_before,omitempty"`
	CellStatusAfter             SecureCellStatus               `json:"cell_status_after,omitempty"`
	ParticipantStatusBefore     SecureCellParticipantStatus    `json:"participant_status_before,omitempty"`
	ParticipantStatusAfter      SecureCellParticipantStatus    `json:"participant_status_after,omitempty"`
	TransitionID                string                         `json:"transition_id"`
	TransitionCount             int                            `json:"transition_count"`
	ParticipantCount            int                            `json:"participant_count"`
	SessionCount                int                            `json:"session_count"`
	ActiveSessionCount          int                            `json:"active_session_count"`
	ThreadCount                 int                            `json:"thread_count"`
	ActiveThreadCount           int                            `json:"active_thread_count"`
	DecisionCount               int                            `json:"decision_count"`
	OpenDecisionCount           int                            `json:"open_decision_count"`
	ApprovedDecisionCount       int                            `json:"approved_decision_count"`
	QuorumFailedDecisionCount   int                            `json:"quorum_failed_decision_count"`
	QuarantinedDecisionCount    int                            `json:"quarantined_decision_count"`
	SharedOutputCount           int                            `json:"shared_output_count"`
	SessionExchangeCount        int                            `json:"session_exchange_count"`
	ActiveParticipantCount      int                            `json:"active_participant_count"`
	QuarantinedParticipantCount int                            `json:"quarantined_participant_count"`
	RevokedParticipantCount     int                            `json:"revoked_participant_count"`
	PolicyReceiptID             string                         `json:"policy_receipt_id,omitempty"`
	PolicyReceiptContentHash    string                         `json:"policy_receipt_content_hash,omitempty"`
	ReceiptChainHash            string                         `json:"receipt_chain_hash,omitempty"`
	SealID                      string                         `json:"seal_id,omitempty"`
	ControlLedgerID             string                         `json:"control_ledger_id,omitempty"`
	ControlLedgerContentHash    string                         `json:"control_ledger_content_hash,omitempty"`
	PortablePackageHash         string                         `json:"portable_package_hash,omitempty"`
	PortablePackageSigned       bool                           `json:"portable_package_signed"`
	PortablePackageAnchored     bool                           `json:"portable_package_anchored"`
	Reason                      string                         `json:"reason,omitempty"`
	Metadata                    map[string]string              `json:"metadata,omitempty"`
	OccurredAt                  time.Time                      `json:"occurred_at"`
	PublishedAt                 time.Time                      `json:"published_at"`
}

// SecureCellAdmissionRequest admits a new member into a live secure cell.
type SecureCellAdmissionRequest struct {
	Participant SecureCellParticipant `json:"participant"`
	ActorDID    string                `json:"actor_did,omitempty"`
	Reason      string                `json:"reason,omitempty"`
	Metadata    map[string]string     `json:"metadata,omitempty"`
}

// SecureCellMemberTransitionRequest mutates the live posture of an existing
// member.
type SecureCellMemberTransitionRequest struct {
	ParticipantDID      string            `json:"participant_did"`
	ActorDID            string            `json:"actor_did,omitempty"`
	Reason              string            `json:"reason,omitempty"`
	QuarantineExpiresAt *time.Time        `json:"quarantine_expires_at,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

// SecureCellLifecycleRequest mutates the cell's own lifecycle posture.
type SecureCellLifecycleRequest struct {
	ActorDID string            `json:"actor_did,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecureCellSessionStartRequest starts a new governed collaboration session
// scoped within a secure cell.
type SecureCellSessionStartRequest struct {
	ActorDID        string            `json:"actor_did,omitempty"`
	Name            string            `json:"name,omitempty"`
	Purpose         string            `json:"purpose,omitempty"`
	ParticipantDIDs []string          `json:"participant_dids,omitempty"`
	DataClasses     []string          `json:"data_classes,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// SecureCellSessionShareRequest records one policy-bound shared output inside
// a secure session.
type SecureCellSessionShareRequest struct {
	ActorDID       string            `json:"actor_did,omitempty"`
	SessionID      string            `json:"session_id,omitempty"`
	Name           string            `json:"name,omitempty"`
	ArtifactType   string            `json:"artifact_type,omitempty"`
	Classification string            `json:"classification,omitempty"`
	Resource       string            `json:"resource,omitempty"`
	Summary        string            `json:"summary,omitempty"`
	SharedWith     []string          `json:"shared_with,omitempty"`
	IntegrityHash  string            `json:"integrity_hash,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// SecureCellSessionExchangeRequest records one policy-bound message or
// exchange artifact inside a secure session.
type SecureCellSessionExchangeRequest struct {
	ActorDID       string            `json:"actor_did,omitempty"`
	SessionID      string            `json:"session_id,omitempty"`
	Name           string            `json:"name,omitempty"`
	ExchangeType   string            `json:"exchange_type,omitempty"`
	Classification string            `json:"classification,omitempty"`
	Resource       string            `json:"resource,omitempty"`
	Summary        string            `json:"summary,omitempty"`
	Recipients     []string          `json:"recipients,omitempty"`
	IntegrityHash  string            `json:"integrity_hash,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// SecureCellSessionThreadStartRequest starts a governed collaboration thread
// within one session.
type SecureCellSessionThreadStartRequest struct {
	ActorDID        string            `json:"actor_did,omitempty"`
	SessionID       string            `json:"session_id,omitempty"`
	Name            string            `json:"name,omitempty"`
	Purpose         string            `json:"purpose,omitempty"`
	ParticipantDIDs []string          `json:"participant_dids,omitempty"`
	DataClasses     []string          `json:"data_classes,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// SecureCellThreadMessageRequest records one evidence-bearing message inside a
// thread.
type SecureCellThreadMessageRequest struct {
	ActorDID       string            `json:"actor_did,omitempty"`
	SessionID      string            `json:"session_id,omitempty"`
	ThreadID       string            `json:"thread_id,omitempty"`
	Name           string            `json:"name,omitempty"`
	ExchangeType   string            `json:"exchange_type,omitempty"`
	Classification string            `json:"classification,omitempty"`
	Resource       string            `json:"resource,omitempty"`
	Summary        string            `json:"summary,omitempty"`
	Recipients     []string          `json:"recipients,omitempty"`
	IntegrityHash  string            `json:"integrity_hash,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// SecureCellThreadDecisionRequest creates one governed decision object inside
// a collaboration thread.
type SecureCellThreadDecisionRequest struct {
	ActorDID              string                               `json:"actor_did,omitempty"`
	SessionID             string                               `json:"session_id,omitempty"`
	ThreadID              string                               `json:"thread_id,omitempty"`
	Title                 string                               `json:"title,omitempty"`
	Summary               string                               `json:"summary,omitempty"`
	Classification        string                               `json:"classification,omitempty"`
	GovernanceTemplate    string                               `json:"governance_template,omitempty"`
	SLATemplate           string                               `json:"sla_template,omitempty"`
	SectorPolicyPack      string                               `json:"sector_policy_pack,omitempty"`
	ApprovalThreshold     int                                  `json:"approval_threshold,omitempty"`
	EligibleApproverDIDs  []string                             `json:"eligible_approver_dids,omitempty"`
	RequiredApproverRoles []string                             `json:"required_approver_roles,omitempty"`
	AllowedVoteChoices    []SecureCellThreadDecisionVoteChoice `json:"allowed_vote_choices,omitempty"`
	RejectorRoles         []string                             `json:"rejector_roles,omitempty"`
	AbstainerRoles        []string                             `json:"abstainer_roles,omitempty"`
	ReopenRoles           []string                             `json:"reopen_roles,omitempty"`
	EscalationLadder      []SecureCellDecisionEscalationTier   `json:"escalation_ladder,omitempty"`
	AutoEscalateToDID     string                               `json:"auto_escalate_to_did,omitempty"`
	EscalationDueAt       *time.Time                           `json:"escalation_due_at,omitempty"`
	ResolutionDueAt       *time.Time                           `json:"resolution_due_at,omitempty"`
	RelatedExchangeIDs    []string                             `json:"related_exchange_ids,omitempty"`
	RelatedOutputIDs      []string                             `json:"related_output_ids,omitempty"`
	Reason                string                               `json:"reason,omitempty"`
	Metadata              map[string]string                    `json:"metadata,omitempty"`
}

// SecureCellThreadDecisionCommentRequest records one evidence-bearing comment
// inside an active governed decision flow.
type SecureCellThreadDecisionCommentRequest struct {
	ActorDID string            `json:"actor_did,omitempty"`
	Comment  string            `json:"comment,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecureCellThreadDecisionDelegationRequest delegates or escalates one
// decision actor into the governed decision flow.
type SecureCellThreadDecisionDelegationRequest struct {
	ActorDID  string            `json:"actor_did,omitempty"`
	TargetDID string            `json:"target_did,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// SecureCellThreadDecisionOutcomeRequest publishes one decision-linked
// outcome bundle across selected outputs and exchanges.
type SecureCellThreadDecisionOutcomeRequest struct {
	ActorDID           string            `json:"actor_did,omitempty"`
	Title              string            `json:"title,omitempty"`
	Summary            string            `json:"summary,omitempty"`
	Classification     string            `json:"classification,omitempty"`
	OutcomeType        string            `json:"outcome_type,omitempty"`
	RelatedExchangeIDs []string          `json:"related_exchange_ids,omitempty"`
	RelatedOutputIDs   []string          `json:"related_output_ids,omitempty"`
	Reason             string            `json:"reason,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// SecureCellSessionMemberTransitionRequest mutates one session's explicit
// membership without changing the parent cell membership.
type SecureCellSessionMemberTransitionRequest struct {
	ParticipantDID string            `json:"participant_did"`
	ActorDID       string            `json:"actor_did,omitempty"`
	Reason         string            `json:"reason,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// SecureCellBulkMemberTransitionRequest applies one member lifecycle action to
// multiple participants within the same cell.
type SecureCellBulkMemberTransitionRequest struct {
	ParticipantDIDs     []string          `json:"participant_dids,omitempty"`
	ActorDID            string            `json:"actor_did,omitempty"`
	Reason              string            `json:"reason,omitempty"`
	QuarantineExpiresAt *time.Time        `json:"quarantine_expires_at,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

// SecureCellBulkMemberTransitionItem is the per-participant outcome from a
// bulk lifecycle operation.
type SecureCellBulkMemberTransitionItem struct {
	ParticipantDID string                      `json:"participant_did"`
	Status         SecureCellParticipantStatus `json:"status,omitempty"`
	Result         string                      `json:"result"`
	Error          string                      `json:"error,omitempty"`
}

// SecureCellBulkMemberTransitionResult summarizes a bulk lifecycle action.
type SecureCellBulkMemberTransitionResult struct {
	CellID         string                               `json:"cell_id"`
	Action         string                               `json:"action"`
	RequestedCount int                                  `json:"requested_count"`
	SucceededCount int                                  `json:"succeeded_count"`
	FailedCount    int                                  `json:"failed_count"`
	Results        []SecureCellBulkMemberTransitionItem `json:"results,omitempty"`
	FinalState     *SecureCellResult                    `json:"final_state,omitempty"`
}

// SecureCellExpirySweepRelease records one participant released by an expiry
// sweep.
type SecureCellExpirySweepRelease struct {
	CellID         string    `json:"cell_id"`
	ParticipantDID string    `json:"participant_did"`
	ReleasedAt     time.Time `json:"released_at"`
}

// SecureCellExpirySweepResult summarizes a global quarantine-expiry sweep.
type SecureCellExpirySweepResult struct {
	At                   time.Time                      `json:"at"`
	CellsScanned         int                            `json:"cells_scanned"`
	CellsMutated         int                            `json:"cells_mutated"`
	ParticipantsReleased int                            `json:"participants_released"`
	CellIDs              []string                       `json:"cell_ids,omitempty"`
	Releases             []SecureCellExpirySweepRelease `json:"releases,omitempty"`
}

// SecureCellDecisionGovernanceSweepAction records one automated governance
// action applied to a secure-cell decision.
type SecureCellDecisionGovernanceSweepAction struct {
	CellID     string     `json:"cell_id"`
	SessionID  string     `json:"session_id"`
	ThreadID   string     `json:"thread_id"`
	DecisionID string     `json:"decision_id"`
	Action     string     `json:"action"`
	TierID     string     `json:"tier_id,omitempty"`
	TargetDID  string     `json:"target_did,omitempty"`
	DueAt      *time.Time `json:"due_at,omitempty"`
	Trigger    string     `json:"trigger,omitempty"`
	OccurredAt time.Time  `json:"occurred_at"`
}

// SecureCellDecisionGovernanceSweepResult summarizes one global decision
// governance sweep across live secure cells.
type SecureCellDecisionGovernanceSweepResult struct {
	At                 time.Time                                 `json:"at"`
	CellsScanned       int                                       `json:"cells_scanned"`
	DecisionsScanned   int                                       `json:"decisions_scanned"`
	CellsMutated       int                                       `json:"cells_mutated"`
	DecisionsEscalated int                                       `json:"decisions_escalated"`
	DecisionsClosed    int                                       `json:"decisions_closed"`
	CellIDs            []string                                  `json:"cell_ids,omitempty"`
	Actions            []SecureCellDecisionGovernanceSweepAction `json:"actions,omitempty"`
}

// SecureCellOverdueDecisionFilter narrows operator queries for overdue
// decision automation work.
type SecureCellOverdueDecisionFilter struct {
	CellID           string                           `json:"cell_id,omitempty"`
	Jurisdiction     string                           `json:"jurisdiction,omitempty"`
	ParticipantDID   string                           `json:"participant_did,omitempty"`
	SLATemplate      string                           `json:"sla_template,omitempty"`
	SectorPolicyPack string                           `json:"sector_policy_pack,omitempty"`
	Statuses         []SecureCellThreadDecisionStatus `json:"statuses,omitempty"`
	Before           *time.Time                       `json:"before,omitempty"`
	Limit            int                              `json:"limit,omitempty"`
}

// SecureCellOverdueDecision is the operator-facing projection of one decision
// that has crossed an automation deadline.
type SecureCellOverdueDecision struct {
	CellID             string                         `json:"cell_id"`
	Name               string                         `json:"name"`
	Jurisdiction       string                         `json:"jurisdiction"`
	CellStatus         SecureCellStatus               `json:"cell_status"`
	SessionID          string                         `json:"session_id"`
	ThreadID           string                         `json:"thread_id"`
	DecisionID         string                         `json:"decision_id"`
	DecisionTitle      string                         `json:"decision_title"`
	DecisionStatus     SecureCellThreadDecisionStatus `json:"decision_status"`
	GovernanceTemplate string                         `json:"governance_template,omitempty"`
	SLATemplate        string                         `json:"sla_template,omitempty"`
	SectorPolicyPack   string                         `json:"sector_policy_pack,omitempty"`
	AutomationAction   string                         `json:"automation_action"`
	OverdueReason      string                         `json:"overdue_reason"`
	TierID             string                         `json:"tier_id,omitempty"`
	TargetDID          string                         `json:"target_did,omitempty"`
	DueAt              time.Time                      `json:"due_at"`
	OverdueSeconds     int64                          `json:"overdue_seconds"`
	EscalationDueAt    *time.Time                     `json:"escalation_due_at,omitempty"`
	ResolutionDueAt    *time.Time                     `json:"resolution_due_at,omitempty"`
	UpdatedAt          time.Time                      `json:"updated_at"`
}

// SecureCellDecisionAutomationActionFilter narrows operator queries over
// automated decision actions already applied to secure cells.
type SecureCellDecisionAutomationActionFilter struct {
	CellID           string     `json:"cell_id,omitempty"`
	SessionID        string     `json:"session_id,omitempty"`
	ThreadID         string     `json:"thread_id,omitempty"`
	DecisionID       string     `json:"decision_id,omitempty"`
	SLATemplate      string     `json:"sla_template,omitempty"`
	SectorPolicyPack string     `json:"sector_policy_pack,omitempty"`
	Action           string     `json:"action,omitempty"`
	Since            *time.Time `json:"since,omitempty"`
	Until            *time.Time `json:"until,omitempty"`
	Limit            int        `json:"limit,omitempty"`
}

// SecureCellDecisionAutomationActionRecord projects one automated escalation
// or closure action from the decision lifecycle trail.
type SecureCellDecisionAutomationActionRecord struct {
	CellID               string                         `json:"cell_id"`
	Name                 string                         `json:"name"`
	Jurisdiction         string                         `json:"jurisdiction"`
	CellStatus           SecureCellStatus               `json:"cell_status"`
	SessionID            string                         `json:"session_id,omitempty"`
	ThreadID             string                         `json:"thread_id,omitempty"`
	DecisionID           string                         `json:"decision_id,omitempty"`
	DecisionTitle        string                         `json:"decision_title,omitempty"`
	GovernanceTemplate   string                         `json:"governance_template,omitempty"`
	SLATemplate          string                         `json:"sla_template,omitempty"`
	SectorPolicyPack     string                         `json:"sector_policy_pack,omitempty"`
	DecisionStatusBefore SecureCellThreadDecisionStatus `json:"decision_status_before,omitempty"`
	DecisionStatusAfter  SecureCellThreadDecisionStatus `json:"decision_status_after,omitempty"`
	Action               string                         `json:"action"`
	TierID               string                         `json:"tier_id,omitempty"`
	TargetDID            string                         `json:"target_did,omitempty"`
	Trigger              string                         `json:"trigger,omitempty"`
	DueAt                *time.Time                     `json:"due_at,omitempty"`
	Actor                string                         `json:"actor"`
	AutomatedActor       string                         `json:"automated_actor,omitempty"`
	Reason               string                         `json:"reason,omitempty"`
	TransitionID         string                         `json:"transition_id"`
	OccurredAt           time.Time                      `json:"occurred_at"`
	Metadata             map[string]string              `json:"metadata,omitempty"`
}

// SecureCellListFilter narrows collection queries over live secure cells.
type SecureCellListFilter struct {
	Statuses       []SecureCellStatus `json:"statuses,omitempty"`
	Jurisdiction   string             `json:"jurisdiction,omitempty"`
	ParticipantDID string             `json:"participant_did,omitempty"`
	UpdatedAfter   *time.Time         `json:"updated_after,omitempty"`
	UpdatedBefore  *time.Time         `json:"updated_before,omitempty"`
	Limit          int                `json:"limit,omitempty"`
}

// SecureCellSummary is the operator-facing projection used for collection
// listings without returning the full artifact bundle.
type SecureCellSummary struct {
	CellID                      string           `json:"cell_id"`
	Name                        string           `json:"name"`
	Purpose                     string           `json:"purpose"`
	Jurisdiction                string           `json:"jurisdiction"`
	Status                      SecureCellStatus `json:"status"`
	PausedFromStatus            SecureCellStatus `json:"paused_from_status,omitempty"`
	ParticipantCount            int              `json:"participant_count"`
	ActiveParticipantCount      int              `json:"active_participant_count"`
	QuarantinedParticipantCount int              `json:"quarantined_participant_count"`
	RevokedParticipantCount     int              `json:"revoked_participant_count"`
	TransitionCount             int              `json:"transition_count"`
	HasControlLedger            bool             `json:"has_control_ledger"`
	HasPortablePackage          bool             `json:"has_portable_package"`
	NextQuarantineExpiry        *time.Time       `json:"next_quarantine_expiry,omitempty"`
	TerminatedAt                *time.Time       `json:"terminated_at,omitempty"`
	CreatedAt                   time.Time        `json:"created_at"`
	UpdatedAt                   time.Time        `json:"updated_at"`
}

// SecureCellQuarantineExpiry is the operator-facing projection for members who
// are quarantined with explicit expiry windows.
type SecureCellQuarantineExpiry struct {
	CellID         string           `json:"cell_id"`
	Name           string           `json:"name"`
	Jurisdiction   string           `json:"jurisdiction"`
	CellStatus     SecureCellStatus `json:"cell_status"`
	ParticipantDID string           `json:"participant_did"`
	Role           string           `json:"role"`
	Reason         string           `json:"reason,omitempty"`
	ExpiresAt      time.Time        `json:"expires_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

// ServiceConfig configures Secure Cells v1.
type ServiceConfig struct {
	Negotiations                                                         *agent.NegotiationManager
	PolicyEngine                                                         *policy.PolicyEngine
	PolicySet                                                            *policy.PolicySet
	PolicySignerKey                                                      *ecdsa.PrivateKey
	PolicySigner                                                         string
	CredentialIssuerKey                                                  *ecdsa.PrivateKey
	CredentialIssuer                                                     string
	Sealer                                                               SecureCellSealer
	LedgerStore                                                          evidence.ControlLedgerStore
	WorkflowStore                                                        SecureCellStore
	Framework                                                            string
	IncludeVerificationKeys                                              bool
	PackageSigningKey                                                    ed25519.PrivateKey
	PackageSigner                                                        string
	PackageSignerFunc                                                    SecureCellPackageSigner
	FederationAssuranceBundleSigner                                      SecureCellFederationAssuranceBundleSigner
	FederationIncidentBulletinSigner                                     SecureCellFederationIncidentBulletinSigner
	FederationIncidentResponseBundleSigner                               SecureCellFederationIncidentResponseBundleSigner
	FederationIncidentDirectiveBundleSigner                              SecureCellFederationIncidentDirectiveBundleSigner
	FederationIncidentDirectiveExtensionAppealBundleSigner               SecureCellFederationIncidentDirectiveExtensionAppealBundleSigner
	FederationIncidentDirectiveExtensionAppealReconciliationBundleSigner SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleSigner
	FederationIncidentReportBundleSigner                                 SecureCellFederationIncidentReportBundleSigner
	FederationIncidentReportAmendmentBundleSigner                        SecureCellFederationIncidentReportAmendmentBundleSigner
	FederationIncidentReportReconciliationBundleSigner                   SecureCellFederationIncidentReportReconciliationBundleSigner
	FederationIncidentReportAmendmentReconciliationBundleSigner          SecureCellFederationIncidentReportAmendmentReconciliationBundleSigner
	FederationIncidentCasePackSigner                                     SecureCellFederationIncidentCasePackSigner
	PackageAnchorer                                                      SecureCellPackageAnchorer
	EventPublisher                                                       SecureCellEventPublisher
	TrustAnchors                                                         []evidence.PlatformTrustAnchor
	DecisionSLATemplates                                                 []SecureCellDecisionSLATemplate
	ConfidentialAttestor                                                 confidential.Attestor
	ConfidentialPolicy                                                   confidential.Policy
}

type secureCellRun struct {
	request SecureCellRequest
	result  *SecureCellResult
}

// Service creates and serves secure cells.
type Service struct {
	config ServiceConfig

	mu                   sync.RWMutex
	runs                 map[string]*secureCellRun
	decisionSLATemplates []SecureCellDecisionSLATemplate
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
	if config.WorkflowStore == nil {
		config.WorkflowStore = NewInMemorySecureCellStore()
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
	decisionSLATemplates, err := normalizeSecureCellDecisionSLATemplates(config.DecisionSLATemplates)
	if err != nil {
		return nil, fmt.Errorf("securecells/service: normalize decision SLA templates: %w", err)
	}

	service := &Service{
		config:               config,
		runs:                 make(map[string]*secureCellRun),
		decisionSLATemplates: decisionSLATemplates,
	}
	if err := service.loadPersistedRuns(context.Background()); err != nil {
		return nil, fmt.Errorf("securecells/service: load persisted runs: %w", err)
	}
	return service, nil
}

// CreateCell provisions a new secure collaboration cell.
func (s *Service) CreateCell(ctx context.Context, req SecureCellRequest) (*SecureCellResult, error) {
	normalized, err := s.normalizeRequest(req)
	if err != nil {
		return nil, err
	}

	createReceipt, err := s.evaluateStage(ctx, normalized, "create", "", nil, normalized.OwnerIdentity.AgentID())
	if err != nil {
		return nil, err
	}

	result := &SecureCellResult{
		CellID:                  cellID(normalized),
		Name:                    normalized.Name,
		Purpose:                 normalized.Purpose,
		Status:                  SecureCellStatusActive,
		Policy:                  clonePolicy(normalized.Policy),
		CreationReceipt:         cloneSignedPolicyReceipt(createReceipt),
		FederationOrganizations: deriveSecureCellFederationOrganizations(normalized, nil),
		CreatedAt:               time.Now().UTC(),
		UpdatedAt:               time.Now().UTC(),
	}
	run := &secureCellRun{request: normalized, result: result}

	if createReceipt.Decision != policy.Allow.String() {
		result.Status = SecureCellStatusRejected
		result.RejectionReason = "secure cell creation denied by policy"
		if err := s.persistRun(ctx, run); err != nil {
			return nil, err
		}
		s.setRun(run)
		return cloneResult(result)
	}

	participantStates, negotiationSessionIDs, err := s.negotiateParticipants(ctx, normalized)
	if err != nil {
		result.Status = SecureCellStatusRejected
		result.RejectionReason = err.Error()
		if err := s.persistRun(ctx, run); err != nil {
			return nil, err
		}
		s.setRun(run)
		return cloneResult(result)
	}
	result.Participants = participantStates
	result.FederationOrganizations = deriveSecureCellFederationOrganizations(normalized, result.Participants)

	activationReceipt, err := s.evaluateStage(ctx, normalized, "activate", createReceipt.ContentHash, nil, normalized.OwnerIdentity.AgentID())
	if err != nil {
		s.markNegotiationsFailed(ctx, negotiationSessionIDs, err.Error())
		return nil, err
	}
	if activationReceipt.Decision != policy.Allow.String() {
		result.Status = SecureCellStatusRejected
		result.RejectionReason = "secure cell activation denied by policy"
		result.ActivationReceipt = cloneSignedPolicyReceipt(activationReceipt)
		s.markNegotiationsFailed(ctx, negotiationSessionIDs, result.RejectionReason)
		if err := s.persistRun(ctx, run); err != nil {
			return nil, err
		}
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

// StartSession opens a governed collaboration room inside an active secure
// cell and regenerates the sealed evidence package.
func (s *Service) StartSession(ctx context.Context, cellID string, start SecureCellSessionStartRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	if run.result.Status != SecureCellStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: secure cell %q does not permit session start while %s", ErrCellImmutable, run.result.CellID, run.result.Status)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(start.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to start a session", ErrPolicyDenied, actorDID)
	}

	participantDIDs, err := secureCellResolveSessionParticipants(run.result.Participants, start.ParticipantDIDs)
	if err != nil {
		return nil, err
	}
	dataClasses, err := secureCellResolveSessionDataClasses(run.request.Policy, start.DataClasses)
	if err != nil {
		return nil, err
	}

	session := SecureCellSession{
		ID:              secureCellSessionID(run.request, run.result, start.Name, participantDIDs),
		Name:            firstNonEmpty(strings.TrimSpace(start.Name), fmt.Sprintf("%s Session %d", run.result.Name, len(run.result.Sessions)+1)),
		Purpose:         firstNonEmpty(strings.TrimSpace(start.Purpose), run.result.Purpose),
		Status:          SecureCellSessionStatusActive,
		ParticipantDIDs: participantDIDs,
		DataClasses:     dataClasses,
		StartedBy:       actorDID,
		OpenedAt:        time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		Metadata:        cloneStringMap(start.Metadata),
	}

	receipt, err := s.evaluateStage(ctx, run.request, "start_session", lastReceiptHash(run.result), map[string]string{
		"session_id":           session.ID,
		"session_name":         session.Name,
		"session_participants": strings.Join(session.ParticipantDIDs, ","),
		"session_data_classes": strings.Join(session.DataClasses, ","),
		"cell_status_before":   string(run.result.Status),
		"transition_reason":    strings.TrimSpace(start.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}
	run.result.Sessions = append(run.result.Sessions, session)
	run.result.UpdatedAt = session.UpdatedAt

	transition := SecureCellTransition{
		ID:                  transitionID(run.request, "session_started", session.ID),
		Action:              "secure_cell.session_started",
		Actor:               actorDID,
		TargetType:          "session",
		TargetDID:           session.ID,
		SessionID:           session.ID,
		SessionStatusBefore: "",
		SessionStatusAfter:  session.Status,
		CellStatusBefore:    run.result.Status,
		CellStatusAfter:     run.result.Status,
		PolicyReceipt:       cloneSignedPolicyReceipt(receipt),
		Reason:              strings.TrimSpace(start.Reason),
		Metadata:            cloneStringMap(start.Metadata),
		OccurredAt:          receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// StartThread opens one governed collaboration stream inside an active
// session.
func (s *Service) StartThread(ctx context.Context, cellID string, start SecureCellSessionThreadStartRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	if run.result.Status != SecureCellStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: secure cell %q does not permit thread start while %s", ErrCellImmutable, run.result.CellID, run.result.Status)
	}

	sessionIdx, session := findSecureCellSession(run.result.Sessions, start.SessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, start.SessionID)
	}
	if session.Status != SecureCellSessionStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: session %q is not active", ErrSessionNotActive, start.SessionID)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(start.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellSessionActorAllowed(run, *session, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to start a thread in session %q", ErrPolicyDenied, actorDID, session.ID)
	}

	participantDIDs, err := secureCellResolveThreadParticipants(run.result.Participants, *session, start.ParticipantDIDs)
	if err != nil {
		return nil, err
	}
	dataClasses, err := secureCellResolveThreadDataClasses(*session, start.DataClasses)
	if err != nil {
		return nil, err
	}

	thread := SecureCellSessionThread{
		ID:              secureCellSessionThreadID(run.request, *session, start.Name, participantDIDs, run.result.Threads),
		SessionID:       session.ID,
		Name:            firstNonEmpty(strings.TrimSpace(start.Name), fmt.Sprintf("%s Thread %d", session.Name, len(run.result.Threads)+1)),
		Purpose:         firstNonEmpty(strings.TrimSpace(start.Purpose), session.Purpose),
		Status:          SecureCellThreadStatusActive,
		ParticipantDIDs: participantDIDs,
		DataClasses:     dataClasses,
		StartedBy:       actorDID,
		OpenedAt:        time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		Metadata:        cloneStringMap(start.Metadata),
	}

	receipt, err := s.evaluateStage(ctx, run.request, "start_session_thread", lastReceiptHash(run.result), map[string]string{
		"session_id":            session.ID,
		"thread_id":             thread.ID,
		"thread_name":           thread.Name,
		"thread_participants":   strings.Join(thread.ParticipantDIDs, ","),
		"thread_data_classes":   strings.Join(thread.DataClasses, ","),
		"session_status_before": string(session.Status),
		"cell_status_before":    string(run.result.Status),
		"transition_reason":     strings.TrimSpace(start.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	run.result.Threads = append(run.result.Threads, thread)
	run.result.Sessions[sessionIdx].UpdatedAt = time.Now().UTC()
	run.result.UpdatedAt = run.result.Sessions[sessionIdx].UpdatedAt

	transition := SecureCellTransition{
		ID:                  transitionID(run.request, "session_thread_started", thread.ID),
		Action:              "secure_cell.session_thread_started",
		Actor:               actorDID,
		TargetType:          "thread",
		TargetDID:           thread.ID,
		SessionID:           session.ID,
		ThreadID:            thread.ID,
		SessionStatusBefore: session.Status,
		SessionStatusAfter:  session.Status,
		ThreadStatusBefore:  "",
		ThreadStatusAfter:   thread.Status,
		CellStatusBefore:    run.result.Status,
		CellStatusAfter:     run.result.Status,
		PolicyReceipt:       cloneSignedPolicyReceipt(receipt),
		Reason:              strings.TrimSpace(start.Reason),
		Metadata:            cloneStringMap(start.Metadata),
		OccurredAt:          receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// ShareOutput records one policy-bound shared output inside an active secure
// session and regenerates the sealed evidence package.
func (s *Service) ShareOutput(ctx context.Context, cellID string, share SecureCellSessionShareRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	if run.result.Status != SecureCellStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: secure cell %q does not permit session sharing while %s", ErrCellImmutable, run.result.CellID, run.result.Status)
	}

	sessionIdx, session := findSecureCellSession(run.result.Sessions, share.SessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, share.SessionID)
	}
	if session.Status != SecureCellSessionStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: session %q is not active", ErrSessionNotActive, share.SessionID)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(share.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellSessionActorAllowed(run, *session, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to share from session %q", ErrPolicyDenied, actorDID, session.ID)
	}
	sharedWith, err := secureCellResolveSessionRecipients(run.result.Participants, *session, share.SharedWith)
	if err != nil {
		return nil, err
	}
	classification, err := secureCellResolveOutputClassification(run.request.Policy, *session, share.Classification)
	if err != nil {
		return nil, err
	}
	federationAuth, err := secureCellAuthorizeFederatedExchange(run, actorDID, sharedWith, session.ID, classification, secureCellFederationContractActionShareOutput)
	if err != nil {
		return nil, err
	}

	outputID := secureCellSharedOutputID(run.request, *session, share.Name, actorDID, run.result.SharedOutputs)
	output := SecureCellSharedOutput{
		ID:                    outputID,
		SessionID:             session.ID,
		Name:                  firstNonEmpty(strings.TrimSpace(share.Name), fmt.Sprintf("%s Output %d", session.Name, len(session.SharedOutputIDs)+1)),
		ArtifactType:          firstNonEmpty(strings.TrimSpace(share.ArtifactType), "decision_packet"),
		Classification:        classification,
		Resource:              firstNonEmpty(strings.TrimSpace(share.Resource), fmt.Sprintf("secure-cell:%s:session:%s:output:%s", run.result.CellID, session.ID, outputID)),
		Summary:               strings.TrimSpace(share.Summary),
		ProducedBy:            actorDID,
		SharedWith:            sharedWith,
		FederationContractIDs: append([]string(nil), federationAuth.ContractIDs...),
		FederationOrgIDs:      append([]string(nil), federationAuth.OrganizationIDs...),
		IntegrityHash:         secureCellResolveOutputIntegrityHash(share, outputID, session.ID, actorDID, sharedWith),
		ContainmentStatus:     SecureCellArtifactContainmentStatusActive,
		CreatedAt:             time.Now().UTC(),
		Metadata:              mergeStringMaps(share.Metadata, federationAuth.metadata()),
	}
	custody, err := secureCellBuildOutputCustody(output.ProducedBy, output.SharedWith)
	if err != nil {
		return nil, err
	}
	output.ChainOfCustody = custody

	receipt, err := s.evaluateStage(ctx, run.request, "share_session_output", lastReceiptHash(run.result), map[string]string{
		"session_id":                   session.ID,
		"shared_output_id":             output.ID,
		"shared_output_name":           output.Name,
		"shared_output_type":           output.ArtifactType,
		"shared_output_classification": output.Classification,
		"shared_with":                  strings.Join(output.SharedWith, ","),
		"federation_contract_ids":      strings.Join(output.FederationContractIDs, ","),
		"federation_org_ids":           strings.Join(output.FederationOrgIDs, ","),
		"cell_status_before":           string(run.result.Status),
		"transition_reason":            strings.TrimSpace(share.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}
	run.result.SharedOutputs = append(run.result.SharedOutputs, output)
	run.result.Sessions[sessionIdx].SharedOutputIDs = append(run.result.Sessions[sessionIdx].SharedOutputIDs, output.ID)
	run.result.Sessions[sessionIdx].UpdatedAt = time.Now().UTC()
	run.result.UpdatedAt = run.result.Sessions[sessionIdx].UpdatedAt
	run.result.SharedOutputs[len(run.result.SharedOutputs)-1].PolicyReceiptID = receipt.ID
	run.result.SharedOutputs[len(run.result.SharedOutputs)-1].PolicyReceiptHash = receipt.ContentHash

	transition := SecureCellTransition{
		ID:                  transitionID(run.request, "session_shared", output.ID),
		Action:              "secure_cell.session_shared",
		Actor:               actorDID,
		TargetType:          "shared_output",
		TargetDID:           output.ID,
		SessionID:           session.ID,
		SharedOutputID:      output.ID,
		SessionStatusBefore: session.Status,
		SessionStatusAfter:  session.Status,
		CellStatusBefore:    run.result.Status,
		CellStatusAfter:     run.result.Status,
		PolicyReceipt:       cloneSignedPolicyReceipt(receipt),
		Reason:              strings.TrimSpace(share.Reason),
		Metadata:            mergeStringMaps(share.Metadata, federationAuth.metadata()),
		OccurredAt:          receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	if lastTransition := lastSecureCellTransition(run.result); lastTransition != nil && lastTransition.SharedOutputID == output.ID {
		lastIdx := len(run.result.SharedOutputs) - 1
		run.result.SharedOutputs[lastIdx].SealID = safeString(lastTransition.ExecutionSeal, func(in *evidence.Seal) string { return in.SealID })
		run.result.SharedOutputs[lastIdx].TraceLinkID = safeString(lastTransition.TraceLink, func(in *evidence.TraceLink) string { return in.ID })
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// CloseSession closes a collaboration session while preserving its full
// portable evidence history.
func (s *Service) CloseSession(ctx context.Context, cellID string, lifecycle SecureCellLifecycleRequest, sessionID string) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	sessionIdx, session := findSecureCellSession(run.result.Sessions, sessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
	}
	if !sessionStatusAllowed(session.Status, SecureCellSessionStatusActive, SecureCellSessionStatusPaused, SecureCellSessionStatusQuarantined) {
		return nil, fmt.Errorf("securecells/service: %w: session %q cannot close while %s", ErrSessionImmutable, sessionID, session.Status)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellSessionActorAllowed(run, *session, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to close session %q", ErrPolicyDenied, actorDID, sessionID)
	}

	receipt, err := s.evaluateStage(ctx, run.request, "close_session", lastReceiptHash(run.result), map[string]string{
		"session_id":            session.ID,
		"cell_status_before":    string(run.result.Status),
		"session_status_before": string(session.Status),
		"transition_reason":     strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	closedAt := time.Now().UTC()
	run.result.Sessions[sessionIdx].Status = SecureCellSessionStatusClosed
	run.result.Sessions[sessionIdx].ClosedBy = actorDID
	run.result.Sessions[sessionIdx].ClosedAt = &closedAt
	run.result.Sessions[sessionIdx].UpdatedAt = closedAt
	run.result.UpdatedAt = closedAt

	transition := SecureCellTransition{
		ID:                  transitionID(run.request, "session_closed", session.ID),
		Action:              "secure_cell.session_closed",
		Actor:               actorDID,
		TargetType:          "session",
		TargetDID:           session.ID,
		SessionID:           session.ID,
		SessionStatusBefore: session.Status,
		SessionStatusAfter:  SecureCellSessionStatusClosed,
		CellStatusBefore:    run.result.Status,
		CellStatusAfter:     run.result.Status,
		PolicyReceipt:       cloneSignedPolicyReceipt(receipt),
		Reason:              strings.TrimSpace(lifecycle.Reason),
		Metadata:            cloneStringMap(lifecycle.Metadata),
		OccurredAt:          receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// RecordExchange records one policy-bound exchange artifact inside an active
// secure session and regenerates the sealed evidence package.
func (s *Service) RecordExchange(ctx context.Context, cellID string, exchange SecureCellSessionExchangeRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	if run.result.Status != SecureCellStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: secure cell %q does not permit session exchange while %s", ErrCellImmutable, run.result.CellID, run.result.Status)
	}

	sessionIdx, session := findSecureCellSession(run.result.Sessions, exchange.SessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, exchange.SessionID)
	}
	if session.Status != SecureCellSessionStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: session %q is not active", ErrSessionNotActive, exchange.SessionID)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(exchange.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellSessionActorAllowed(run, *session, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to exchange in session %q", ErrPolicyDenied, actorDID, session.ID)
	}
	recipients, err := secureCellResolveSessionRecipients(run.result.Participants, *session, exchange.Recipients)
	if err != nil {
		return nil, err
	}
	classification, err := secureCellResolveOutputClassification(run.request.Policy, *session, exchange.Classification)
	if err != nil {
		return nil, err
	}
	federationAuth, err := secureCellAuthorizeFederatedExchange(run, actorDID, recipients, session.ID, classification, secureCellFederationContractActionSessionExchange)
	if err != nil {
		return nil, err
	}

	exchangeID := secureCellSessionExchangeID(run.request, *session, exchange.Name, actorDID, run.result.SessionExchanges)
	item := SecureCellSessionExchange{
		ID:                    exchangeID,
		SessionID:             session.ID,
		Name:                  firstNonEmpty(strings.TrimSpace(exchange.Name), fmt.Sprintf("%s Exchange %d", session.Name, len(session.ExchangeIDs)+1)),
		ExchangeType:          firstNonEmpty(strings.TrimSpace(exchange.ExchangeType), "message"),
		Classification:        classification,
		Resource:              firstNonEmpty(strings.TrimSpace(exchange.Resource), fmt.Sprintf("secure-cell:%s:session:%s:exchange:%s", run.result.CellID, session.ID, exchangeID)),
		Summary:               strings.TrimSpace(exchange.Summary),
		SentBy:                actorDID,
		Recipients:            recipients,
		FederationContractIDs: append([]string(nil), federationAuth.ContractIDs...),
		FederationOrgIDs:      append([]string(nil), federationAuth.OrganizationIDs...),
		IntegrityHash:         secureCellResolveExchangeIntegrityHash(exchange, exchangeID, session.ID, actorDID, recipients),
		ContainmentStatus:     SecureCellArtifactContainmentStatusActive,
		CreatedAt:             time.Now().UTC(),
		Metadata:              mergeStringMaps(exchange.Metadata, federationAuth.metadata()),
	}
	custody, err := secureCellBuildOutputCustody(item.SentBy, item.Recipients)
	if err != nil {
		return nil, err
	}
	item.ChainOfCustody = custody

	receipt, err := s.evaluateStage(ctx, run.request, "exchange_session_message", lastReceiptHash(run.result), map[string]string{
		"session_id":                      session.ID,
		"session_exchange_id":             item.ID,
		"session_exchange_name":           item.Name,
		"session_exchange_type":           item.ExchangeType,
		"session_exchange_classification": item.Classification,
		"session_exchange_recipients":     strings.Join(item.Recipients, ","),
		"federation_contract_ids":         strings.Join(item.FederationContractIDs, ","),
		"federation_org_ids":              strings.Join(item.FederationOrgIDs, ","),
		"cell_status_before":              string(run.result.Status),
		"transition_reason":               strings.TrimSpace(exchange.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	run.result.SessionExchanges = append(run.result.SessionExchanges, item)
	run.result.Sessions[sessionIdx].ExchangeIDs = append(run.result.Sessions[sessionIdx].ExchangeIDs, item.ID)
	run.result.Sessions[sessionIdx].UpdatedAt = time.Now().UTC()
	run.result.UpdatedAt = run.result.Sessions[sessionIdx].UpdatedAt
	run.result.SessionExchanges[len(run.result.SessionExchanges)-1].PolicyReceiptID = receipt.ID
	run.result.SessionExchanges[len(run.result.SessionExchanges)-1].PolicyReceiptHash = receipt.ContentHash

	transition := SecureCellTransition{
		ID:                  transitionID(run.request, "session_exchange", item.ID),
		Action:              "secure_cell.session_exchange",
		Actor:               actorDID,
		TargetType:          "session_exchange",
		TargetDID:           item.ID,
		SessionID:           session.ID,
		SessionExchangeID:   item.ID,
		SessionStatusBefore: session.Status,
		SessionStatusAfter:  session.Status,
		CellStatusBefore:    run.result.Status,
		CellStatusAfter:     run.result.Status,
		PolicyReceipt:       cloneSignedPolicyReceipt(receipt),
		Reason:              strings.TrimSpace(exchange.Reason),
		Metadata:            mergeStringMaps(exchange.Metadata, federationAuth.metadata()),
		OccurredAt:          receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	if lastTransition := lastSecureCellTransition(run.result); lastTransition != nil && lastTransition.SessionExchangeID == item.ID {
		lastIdx := len(run.result.SessionExchanges) - 1
		run.result.SessionExchanges[lastIdx].SealID = safeString(lastTransition.ExecutionSeal, func(in *evidence.Seal) string { return in.SealID })
		run.result.SessionExchanges[lastIdx].TraceLinkID = safeString(lastTransition.TraceLink, func(in *evidence.TraceLink) string { return in.ID })
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// PostThreadMessage records one evidence-bearing message inside an active
// thread and regenerates the sealed evidence package.
func (s *Service) PostThreadMessage(ctx context.Context, cellID string, message SecureCellThreadMessageRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	if run.result.Status != SecureCellStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: secure cell %q does not permit thread messaging while %s", ErrCellImmutable, run.result.CellID, run.result.Status)
	}

	threadIdx, thread := findSecureCellThread(run.result.Threads, message.ThreadID)
	if thread == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrThreadNotFound, message.ThreadID)
	}
	sessionID := firstNonEmpty(strings.TrimSpace(message.SessionID), thread.SessionID)
	sessionIdx, session := findSecureCellSession(run.result.Sessions, sessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
	}
	if thread.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrThreadNotFound, message.ThreadID)
	}
	if session.Status != SecureCellSessionStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: session %q is not active", ErrSessionNotActive, sessionID)
	}
	if thread.Status != SecureCellThreadStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: thread %q is not active", ErrThreadNotActive, message.ThreadID)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(message.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellThreadActorAllowed(run, *thread, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to message thread %q", ErrPolicyDenied, actorDID, thread.ID)
	}
	recipients, err := secureCellResolveThreadRecipients(run.result.Participants, *thread, message.Recipients)
	if err != nil {
		return nil, err
	}
	classification, err := secureCellResolveThreadClassification(*thread, message.Classification)
	if err != nil {
		return nil, err
	}
	federationAuth, err := secureCellAuthorizeFederatedExchange(run, actorDID, recipients, session.ID, classification, secureCellFederationContractActionThreadMessage)
	if err != nil {
		return nil, err
	}

	exchangeID := secureCellThreadMessageID(run.request, *session, *thread, message.Name, actorDID, run.result.SessionExchanges)
	item := SecureCellSessionExchange{
		ID:                    exchangeID,
		SessionID:             session.ID,
		ThreadID:              thread.ID,
		Name:                  firstNonEmpty(strings.TrimSpace(message.Name), fmt.Sprintf("%s Message %d", thread.Name, len(thread.ExchangeIDs)+1)),
		ExchangeType:          firstNonEmpty(strings.TrimSpace(message.ExchangeType), "thread_message"),
		Classification:        classification,
		Resource:              firstNonEmpty(strings.TrimSpace(message.Resource), fmt.Sprintf("secure-cell:%s:session:%s:thread:%s:message:%s", run.result.CellID, session.ID, thread.ID, exchangeID)),
		Summary:               strings.TrimSpace(message.Summary),
		SentBy:                actorDID,
		Recipients:            recipients,
		FederationContractIDs: append([]string(nil), federationAuth.ContractIDs...),
		FederationOrgIDs:      append([]string(nil), federationAuth.OrganizationIDs...),
		IntegrityHash:         secureCellResolveThreadMessageIntegrityHash(message, exchangeID, session.ID, thread.ID, actorDID, recipients),
		ContainmentStatus:     SecureCellArtifactContainmentStatusActive,
		CreatedAt:             time.Now().UTC(),
		Metadata:              mergeStringMaps(message.Metadata, federationAuth.metadata()),
	}
	custody, err := secureCellBuildOutputCustody(item.SentBy, item.Recipients)
	if err != nil {
		return nil, err
	}
	item.ChainOfCustody = custody

	receipt, err := s.evaluateStage(ctx, run.request, "message_session_thread", lastReceiptHash(run.result), map[string]string{
		"session_id":                    session.ID,
		"thread_id":                     thread.ID,
		"session_exchange_id":           item.ID,
		"thread_message_name":           item.Name,
		"thread_message_type":           item.ExchangeType,
		"thread_message_classification": item.Classification,
		"thread_message_recipients":     strings.Join(item.Recipients, ","),
		"federation_contract_ids":       strings.Join(item.FederationContractIDs, ","),
		"federation_org_ids":            strings.Join(item.FederationOrgIDs, ","),
		"thread_status_before":          string(thread.Status),
		"session_status_before":         string(session.Status),
		"cell_status_before":            string(run.result.Status),
		"transition_reason":             strings.TrimSpace(message.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	run.result.SessionExchanges = append(run.result.SessionExchanges, item)
	run.result.Sessions[sessionIdx].ExchangeIDs = append(run.result.Sessions[sessionIdx].ExchangeIDs, item.ID)
	run.result.Sessions[sessionIdx].UpdatedAt = time.Now().UTC()
	run.result.Threads[threadIdx].ExchangeIDs = append(run.result.Threads[threadIdx].ExchangeIDs, item.ID)
	run.result.Threads[threadIdx].UpdatedAt = run.result.Sessions[sessionIdx].UpdatedAt
	run.result.UpdatedAt = run.result.Sessions[sessionIdx].UpdatedAt
	run.result.SessionExchanges[len(run.result.SessionExchanges)-1].PolicyReceiptID = receipt.ID
	run.result.SessionExchanges[len(run.result.SessionExchanges)-1].PolicyReceiptHash = receipt.ContentHash

	transition := SecureCellTransition{
		ID:                  transitionID(run.request, "session_thread_message", item.ID),
		Action:              "secure_cell.session_thread_message",
		Actor:               actorDID,
		TargetType:          "thread_message",
		TargetDID:           item.ID,
		SessionID:           session.ID,
		ThreadID:            thread.ID,
		SessionExchangeID:   item.ID,
		SessionStatusBefore: session.Status,
		SessionStatusAfter:  session.Status,
		ThreadStatusBefore:  thread.Status,
		ThreadStatusAfter:   thread.Status,
		CellStatusBefore:    run.result.Status,
		CellStatusAfter:     run.result.Status,
		PolicyReceipt:       cloneSignedPolicyReceipt(receipt),
		Reason:              strings.TrimSpace(message.Reason),
		Metadata:            mergeStringMaps(message.Metadata, federationAuth.metadata()),
		OccurredAt:          receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	if lastTransition := lastSecureCellTransition(run.result); lastTransition != nil && lastTransition.SessionExchangeID == item.ID {
		lastIdx := len(run.result.SessionExchanges) - 1
		run.result.SessionExchanges[lastIdx].SealID = safeString(lastTransition.ExecutionSeal, func(in *evidence.Seal) string { return in.SealID })
		run.result.SessionExchanges[lastIdx].TraceLinkID = safeString(lastTransition.TraceLink, func(in *evidence.TraceLink) string { return in.ID })
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// CreateThreadDecision creates one governed decision object inside an active
// collaboration thread.
func (s *Service) CreateThreadDecision(ctx context.Context, cellID string, decision SecureCellThreadDecisionRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	if run.result.Status != SecureCellStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: secure cell %q does not permit thread decisions while %s", ErrCellImmutable, run.result.CellID, run.result.Status)
	}

	threadIdx, thread := findSecureCellThread(run.result.Threads, decision.ThreadID)
	if thread == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrThreadNotFound, decision.ThreadID)
	}
	sessionID := firstNonEmpty(strings.TrimSpace(decision.SessionID), thread.SessionID)
	sessionIdx, session := findSecureCellSession(run.result.Sessions, sessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
	}
	if thread.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrThreadNotFound, decision.ThreadID)
	}
	if session.Status != SecureCellSessionStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: session %q is not active", ErrSessionNotActive, sessionID)
	}
	if thread.Status != SecureCellThreadStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: thread %q is not active", ErrThreadNotActive, decision.ThreadID)
	}
	proposedAt := time.Now().UTC()

	actorDID := firstNonEmpty(strings.TrimSpace(decision.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellThreadActorAllowed(run, *thread, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to create decisions in thread %q", ErrPolicyDenied, actorDID, thread.ID)
	}
	title := strings.TrimSpace(decision.Title)
	if title == "" {
		return nil, fmt.Errorf("securecells/service: thread decision title is required")
	}
	classification, err := secureCellResolveThreadDecisionClassification(*thread, decision.Classification)
	if err != nil {
		return nil, err
	}
	relatedExchangeIDs, err := secureCellResolveThreadDecisionExchangeRefs(*session, *thread, run.result.SessionExchanges, decision.RelatedExchangeIDs)
	if err != nil {
		return nil, err
	}
	relatedOutputIDs, err := secureCellResolveThreadDecisionOutputRefs(*session, run.result.SharedOutputs, decision.RelatedOutputIDs)
	if err != nil {
		return nil, err
	}
	decision, appliedSLATemplate, hasSLATemplate, err := s.applyDecisionSLATemplate(run, *thread, proposedAt, decision)
	if err != nil {
		return nil, err
	}
	approvalThreshold := normalizeSecureCellThreshold(decision.ApprovalThreshold)
	eligibleApproverDIDs := uniqueSecureCellStrings(decision.EligibleApproverDIDs)
	requiredApproverRoles := uniqueSecureCellDecisionRoles(decision.RequiredApproverRoles)
	governanceTemplate, allowedVoteChoices, rejectorRoles, abstainerRoles, reopenRoles, err := resolveSecureCellDecisionGovernance(decision.GovernanceTemplate, decision.AllowedVoteChoices, decision.RejectorRoles, decision.AbstainerRoles, decision.ReopenRoles)
	if err != nil {
		return nil, err
	}
	for _, governedRole := range append(append(append([]string(nil), rejectorRoles...), abstainerRoles...), reopenRoles...) {
		if !secureCellDecisionRoleAvailable(run, *thread, governedRole) {
			return nil, fmt.Errorf("securecells/service: decision governance role %q is not available for thread decision %q", governedRole, title)
		}
	}
	autoEscalateToDID := strings.TrimSpace(decision.AutoEscalateToDID)
	escalationDueAt := cloneUTCTime(decision.EscalationDueAt)
	resolutionDueAt := cloneUTCTime(decision.ResolutionDueAt)
	escalationLadder, err := normalizeSecureCellDecisionEscalationLadder(decision.EscalationLadder, autoEscalateToDID, escalationDueAt)
	if err != nil {
		return nil, err
	}
	for _, tier := range escalationLadder {
		if !secureCellDecisionParticipantAllowed(run, tier.TargetDID) {
			return nil, fmt.Errorf("securecells/service: %w: escalation target %q is not permitted for thread %q", ErrPolicyDenied, tier.TargetDID, thread.ID)
		}
	}
	if autoEscalateToDID == "" && len(escalationLadder) > 0 {
		autoEscalateToDID = escalationLadder[0].TargetDID
	}
	if escalationDueAt == nil && len(escalationLadder) > 0 {
		escalationDueAt = cloneUTCTime(escalationLadder[0].DueAt)
	}
	if autoEscalateToDID != "" && !secureCellDecisionParticipantAllowed(run, autoEscalateToDID) {
		return nil, fmt.Errorf("securecells/service: %w: auto-escalation target %q is not permitted for thread %q", ErrPolicyDenied, autoEscalateToDID, thread.ID)
	}
	if escalationDueAt != nil && autoEscalateToDID == "" {
		return nil, fmt.Errorf("securecells/service: auto-escalation target is required when escalation_due_at is set")
	}
	lastEscalationDueAt := escalationDueAt
	if len(escalationLadder) > 0 {
		lastEscalationDueAt = cloneUTCTime(escalationLadder[len(escalationLadder)-1].DueAt)
	}
	if lastEscalationDueAt != nil && resolutionDueAt != nil && resolutionDueAt.Before(*lastEscalationDueAt) {
		return nil, fmt.Errorf("securecells/service: resolution due time must be after escalation due time")
	}
	if len(eligibleApproverDIDs) > 0 && len(requiredApproverRoles) == 0 && approvalThreshold > len(eligibleApproverDIDs) {
		return nil, fmt.Errorf("securecells/service: thread decision approval threshold %d exceeds eligible approver count %d", approvalThreshold, len(eligibleApproverDIDs))
	}
	for _, eligibleDID := range eligibleApproverDIDs {
		if !secureCellDecisionParticipantAllowed(run, eligibleDID) {
			return nil, fmt.Errorf("securecells/service: %w: decision approver %q is not permitted for thread %q", ErrPolicyDenied, eligibleDID, thread.ID)
		}
	}
	for _, requiredRole := range requiredApproverRoles {
		if !secureCellDecisionRoleAvailable(run, *thread, requiredRole) {
			return nil, fmt.Errorf("securecells/service: required approver role %q is not available for thread decision %q", requiredRole, title)
		}
	}

	item := SecureCellThreadDecision{
		ID:                    secureCellThreadDecisionID(run.request, *session, *thread, title, actorDID, run.result.Decisions),
		SessionID:             session.ID,
		ThreadID:              thread.ID,
		Title:                 title,
		Summary:               strings.TrimSpace(decision.Summary),
		Classification:        classification,
		GovernanceTemplate:    governanceTemplate,
		SLATemplate:           strings.TrimSpace(decision.SLATemplate),
		SectorPolicyPack:      strings.TrimSpace(decision.SectorPolicyPack),
		Status:                SecureCellThreadDecisionStatusOpen,
		ApprovalThreshold:     approvalThreshold,
		EligibleApproverDIDs:  eligibleApproverDIDs,
		RequiredApproverRoles: requiredApproverRoles,
		AllowedVoteChoices:    allowedVoteChoices,
		RejectorRoles:         rejectorRoles,
		AbstainerRoles:        abstainerRoles,
		ReopenRoles:           reopenRoles,
		EscalationLadder:      escalationLadder,
		AutoEscalateToDID:     autoEscalateToDID,
		ProposedBy:            actorDID,
		RelatedExchangeIDs:    relatedExchangeIDs,
		RelatedOutputIDs:      relatedOutputIDs,
		ProposedAt:            proposedAt,
		EscalationDueAt:       escalationDueAt,
		ResolutionDueAt:       resolutionDueAt,
		UpdatedAt:             proposedAt,
		Metadata:              cloneStringMap(decision.Metadata),
	}

	evaluationMetadata := map[string]string{
		"session_id":                         session.ID,
		"thread_id":                          thread.ID,
		"decision_id":                        item.ID,
		"decision_title":                     item.Title,
		"decision_classification":            item.Classification,
		"decision_governance_template":       item.GovernanceTemplate,
		"decision_sla_template":              item.SLATemplate,
		"decision_sector_policy_pack":        item.SectorPolicyPack,
		"decision_approval_threshold":        fmt.Sprintf("%d", item.ApprovalThreshold),
		"decision_eligible_approvers":        strings.Join(item.EligibleApproverDIDs, ","),
		"decision_required_roles":            strings.Join(item.RequiredApproverRoles, ","),
		"decision_allowed_vote_choices":      joinSecureCellDecisionVoteChoices(item.AllowedVoteChoices),
		"decision_rejector_roles":            strings.Join(item.RejectorRoles, ","),
		"decision_abstainer_roles":           strings.Join(item.AbstainerRoles, ","),
		"decision_reopen_roles":              strings.Join(item.ReopenRoles, ","),
		"decision_escalation_ladder_tiers":   strings.Join(secureCellDecisionEscalationTierIDs(item.EscalationLadder), ","),
		"decision_escalation_ladder_targets": strings.Join(secureCellDecisionEscalationTierTargets(item.EscalationLadder), ","),
		"decision_auto_escalate_to":          item.AutoEscalateToDID,
		"decision_related_exchanges":         strings.Join(item.RelatedExchangeIDs, ","),
		"decision_related_outputs":           strings.Join(item.RelatedOutputIDs, ","),
		"thread_status_before":               string(thread.Status),
		"session_status_before":              string(session.Status),
		"cell_status_before":                 string(run.result.Status),
		"transition_reason":                  strings.TrimSpace(decision.Reason),
	}
	if hasSLATemplate {
		evaluationMetadata["decision_sla_template_name"] = appliedSLATemplate.Name
		evaluationMetadata["decision_sla_template_sector"] = appliedSLATemplate.Sector
	}
	if item.EscalationDueAt != nil {
		evaluationMetadata["decision_escalation_due_at"] = item.EscalationDueAt.UTC().Format(time.RFC3339Nano)
	}
	if item.ResolutionDueAt != nil {
		evaluationMetadata["decision_resolution_due_at"] = item.ResolutionDueAt.UTC().Format(time.RFC3339Nano)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "create_thread_decision", lastReceiptHash(run.result), evaluationMetadata, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	run.result.Decisions = append(run.result.Decisions, item)
	run.result.Threads[threadIdx].DecisionIDs = append(run.result.Threads[threadIdx].DecisionIDs, item.ID)
	run.result.Threads[threadIdx].UpdatedAt = item.UpdatedAt
	run.result.Sessions[sessionIdx].UpdatedAt = item.UpdatedAt
	run.result.UpdatedAt = item.UpdatedAt

	transition := SecureCellTransition{
		ID:                   transitionID(run.request, "session_thread_decision_created", item.ID),
		Action:               "secure_cell.session_thread_decision_created",
		Actor:                actorDID,
		TargetType:           "thread_decision",
		TargetDID:            item.ID,
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		DecisionID:           item.ID,
		SessionStatusBefore:  session.Status,
		SessionStatusAfter:   session.Status,
		ThreadStatusBefore:   thread.Status,
		ThreadStatusAfter:    thread.Status,
		DecisionStatusBefore: "",
		DecisionStatusAfter:  item.Status,
		CellStatusBefore:     run.result.Status,
		CellStatusAfter:      run.result.Status,
		PolicyReceipt:        cloneSignedPolicyReceipt(receipt),
		Reason:               strings.TrimSpace(decision.Reason),
		Metadata:             cloneStringMap(decision.Metadata),
		OccurredAt:           receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// AddSessionMember adds an active cell participant into one existing secure
// collaboration session.
func (s *Service) AddSessionMember(ctx context.Context, cellID string, mutation SecureCellSessionMemberTransitionRequest, sessionID string) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	if run.result.Status != SecureCellStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: secure cell %q does not permit session member admission while %s", ErrCellImmutable, run.result.CellID, run.result.Status)
	}
	sessionIdx, session := findSecureCellSession(run.result.Sessions, sessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
	}
	if session.Status != SecureCellSessionStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: session %q is not active", ErrSessionNotActive, sessionID)
	}
	targetDID := strings.TrimSpace(mutation.ParticipantDID)
	if targetDID == "" {
		return nil, fmt.Errorf("securecells/service: session participant DID is required")
	}
	if secureCellSessionHasParticipant(*session, targetDID) {
		return nil, fmt.Errorf("securecells/service: %w: participant %q already belongs to session %q", ErrSessionParticipantExists, targetDID, sessionID)
	}
	targetState, ok := participantStateForResult(run.result, targetDID)
	if !ok || targetState.Status != SecureCellParticipantStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: participant %q is not an active secure cell participant", ErrSessionParticipantNotFound, targetDID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(mutation.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellSessionActorAllowed(run, *session, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to admit members to session %q", ErrPolicyDenied, actorDID, sessionID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "admit_session_member", lastReceiptHash(run.result), map[string]string{
		"session_id":                  session.ID,
		"target_participant_did":      targetDID,
		"session_status_before":       string(session.Status),
		"session_participants_before": strings.Join(session.ParticipantDIDs, ","),
		"transition_reason":           strings.TrimSpace(mutation.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}
	run.result.Sessions[sessionIdx].ParticipantDIDs = append(run.result.Sessions[sessionIdx].ParticipantDIDs, targetDID)
	run.result.Sessions[sessionIdx].UpdatedAt = time.Now().UTC()
	run.result.UpdatedAt = run.result.Sessions[sessionIdx].UpdatedAt
	transition := SecureCellTransition{
		ID:                  transitionID(run.request, "session_member_admitted", targetDID+"-"+session.ID),
		Action:              "secure_cell.session_member_admitted",
		Actor:               actorDID,
		TargetType:          "session_member",
		TargetDID:           targetDID,
		SessionID:           session.ID,
		SessionStatusBefore: session.Status,
		SessionStatusAfter:  session.Status,
		CellStatusBefore:    run.result.Status,
		CellStatusAfter:     run.result.Status,
		PolicyReceipt:       cloneSignedPolicyReceipt(receipt),
		Reason:              strings.TrimSpace(mutation.Reason),
		Metadata:            cloneStringMap(mutation.Metadata),
		OccurredAt:          receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// RemoveSessionMember removes one participant from an existing session while
// preserving the parent cell membership.
func (s *Service) RemoveSessionMember(ctx context.Context, cellID string, mutation SecureCellSessionMemberTransitionRequest, sessionID string) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	sessionIdx, session := findSecureCellSession(run.result.Sessions, sessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
	}
	if !sessionStatusAllowed(session.Status, SecureCellSessionStatusActive, SecureCellSessionStatusPaused, SecureCellSessionStatusQuarantined) {
		return nil, fmt.Errorf("securecells/service: %w: session %q cannot remove members while %s", ErrSessionImmutable, sessionID, session.Status)
	}
	targetDID := strings.TrimSpace(mutation.ParticipantDID)
	if targetDID == "" {
		return nil, fmt.Errorf("securecells/service: session participant DID is required")
	}
	if !secureCellSessionHasParticipant(*session, targetDID) {
		return nil, fmt.Errorf("securecells/service: %w: participant %q is not part of session %q", ErrSessionParticipantNotFound, targetDID, sessionID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(mutation.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellSessionActorAllowed(run, *session, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to remove members from session %q", ErrPolicyDenied, actorDID, sessionID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "remove_session_member", lastReceiptHash(run.result), map[string]string{
		"session_id":                  session.ID,
		"target_participant_did":      targetDID,
		"session_status_before":       string(session.Status),
		"session_participants_before": strings.Join(session.ParticipantDIDs, ","),
		"transition_reason":           strings.TrimSpace(mutation.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}
	run.result.Sessions[sessionIdx].ParticipantDIDs = removeSecureCellString(run.result.Sessions[sessionIdx].ParticipantDIDs, targetDID)
	run.result.Sessions[sessionIdx].UpdatedAt = time.Now().UTC()
	run.result.UpdatedAt = run.result.Sessions[sessionIdx].UpdatedAt
	transition := SecureCellTransition{
		ID:                  transitionID(run.request, "session_member_removed", targetDID+"-"+session.ID),
		Action:              "secure_cell.session_member_removed",
		Actor:               actorDID,
		TargetType:          "session_member",
		TargetDID:           targetDID,
		SessionID:           session.ID,
		SessionStatusBefore: session.Status,
		SessionStatusAfter:  session.Status,
		CellStatusBefore:    run.result.Status,
		CellStatusAfter:     run.result.Status,
		PolicyReceipt:       cloneSignedPolicyReceipt(receipt),
		Reason:              strings.TrimSpace(mutation.Reason),
		Metadata:            cloneStringMap(mutation.Metadata),
		OccurredAt:          receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) transitionSessionState(
	ctx context.Context,
	cellID string,
	sessionID string,
	lifecycle SecureCellLifecycleRequest,
	stage string,
	targetStatus SecureCellSessionStatus,
	recordAction string,
	allowedStatuses ...SecureCellSessionStatus,
) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	sessionIdx, session := findSecureCellSession(run.result.Sessions, sessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
	}
	if !sessionStatusAllowed(session.Status, allowedStatuses...) {
		return nil, fmt.Errorf("securecells/service: %w: session %q cannot transition from %s via %s", ErrSessionImmutable, sessionID, session.Status, stage)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellSessionActorAllowed(run, *session, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to mutate session %q", ErrPolicyDenied, actorDID, sessionID)
	}
	transitionMetadata := cloneStringMap(lifecycle.Metadata)
	receipt, err := s.evaluateStage(ctx, run.request, stage, lastReceiptHash(run.result), map[string]string{
		"session_id":            session.ID,
		"session_status_before": string(session.Status),
		"session_status_after":  string(targetStatus),
		"cell_status_before":    string(run.result.Status),
		"transition_reason":     strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}
	sessionBefore := session.Status
	pausedFrom := session.PausedFromStatus
	updatedAt := time.Now().UTC()
	run.result.Sessions[sessionIdx].Status = targetStatus
	run.result.Sessions[sessionIdx].UpdatedAt = updatedAt
	switch stage {
	case "pause_session":
		run.result.Sessions[sessionIdx].PausedFromStatus = sessionBefore
	case "resume_session":
		run.result.Sessions[sessionIdx].PausedFromStatus = ""
		run.result.Sessions[sessionIdx].QuarantinedAt = nil
		run.result.Sessions[sessionIdx].ContainedBy = ""
	case "quarantine_session":
		run.result.Sessions[sessionIdx].QuarantinedAt = &updatedAt
		run.result.Sessions[sessionIdx].ContainedBy = actorDID
		if transitionMetadata == nil {
			transitionMetadata = make(map[string]string)
		}
		transitionMetadata["containment_mode"] = "session"
	}
	if stage == "resume_session" && sessionBefore == SecureCellSessionStatusPaused {
		if pausedFrom != "" {
			if transitionMetadata == nil {
				transitionMetadata = make(map[string]string)
			}
			transitionMetadata["paused_from_status"] = string(pausedFrom)
		}
	}
	run.result.UpdatedAt = updatedAt
	transition := SecureCellTransition{
		ID:                  transitionID(run.request, strings.TrimPrefix(recordAction, "secure_cell."), session.ID),
		Action:              recordAction,
		Actor:               actorDID,
		TargetType:          "session",
		TargetDID:           session.ID,
		SessionID:           session.ID,
		SessionStatusBefore: sessionBefore,
		SessionStatusAfter:  targetStatus,
		CellStatusBefore:    run.result.Status,
		CellStatusAfter:     run.result.Status,
		PolicyReceipt:       cloneSignedPolicyReceipt(receipt),
		Reason:              strings.TrimSpace(lifecycle.Reason),
		Metadata:            transitionMetadata,
		OccurredAt:          receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) transitionThreadState(
	ctx context.Context,
	cellID string,
	sessionID string,
	threadID string,
	lifecycle SecureCellLifecycleRequest,
	stage string,
	targetStatus SecureCellThreadStatus,
	recordAction string,
	allowedStatuses ...SecureCellThreadStatus,
) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	sessionIdx, session := findSecureCellSession(run.result.Sessions, sessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
	}
	if session.Status != SecureCellSessionStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: session %q is not active", ErrSessionNotActive, sessionID)
	}
	threadIdx, thread := findSecureCellThread(run.result.Threads, threadID)
	if thread == nil || thread.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrThreadNotFound, threadID)
	}
	if !threadStatusAllowed(thread.Status, allowedStatuses...) {
		return nil, fmt.Errorf("securecells/service: %w: thread %q cannot transition from %s via %s", ErrThreadImmutable, threadID, thread.Status, stage)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellThreadActorAllowed(run, *thread, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to mutate thread %q", ErrPolicyDenied, actorDID, threadID)
	}

	transitionMetadata := cloneStringMap(lifecycle.Metadata)
	receipt, err := s.evaluateStage(ctx, run.request, stage, lastReceiptHash(run.result), map[string]string{
		"session_id":            session.ID,
		"thread_id":             thread.ID,
		"thread_status_before":  string(thread.Status),
		"thread_status_after":   string(targetStatus),
		"session_status_before": string(session.Status),
		"cell_status_before":    string(run.result.Status),
		"transition_reason":     strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	statusBefore := thread.Status
	updatedAt := time.Now().UTC()
	run.result.Threads[threadIdx].Status = targetStatus
	run.result.Threads[threadIdx].UpdatedAt = updatedAt
	switch stage {
	case "quarantine_session_thread":
		run.result.Threads[threadIdx].QuarantinedAt = &updatedAt
		run.result.Threads[threadIdx].ContainedBy = actorDID
		if transitionMetadata == nil {
			transitionMetadata = make(map[string]string)
		}
		transitionMetadata["containment_mode"] = "thread"
	case "resume_session_thread":
		run.result.Threads[threadIdx].QuarantinedAt = nil
		run.result.Threads[threadIdx].ContainedBy = ""
	case "close_session_thread":
		run.result.Threads[threadIdx].ClosedAt = &updatedAt
		run.result.Threads[threadIdx].ClosedBy = actorDID
	}
	run.result.Sessions[sessionIdx].UpdatedAt = updatedAt
	run.result.UpdatedAt = updatedAt

	transition := SecureCellTransition{
		ID:                  transitionID(run.request, strings.TrimPrefix(recordAction, "secure_cell."), thread.ID),
		Action:              recordAction,
		Actor:               actorDID,
		TargetType:          "thread",
		TargetDID:           thread.ID,
		SessionID:           session.ID,
		ThreadID:            thread.ID,
		SessionStatusBefore: session.Status,
		SessionStatusAfter:  session.Status,
		ThreadStatusBefore:  statusBefore,
		ThreadStatusAfter:   targetStatus,
		CellStatusBefore:    run.result.Status,
		CellStatusAfter:     run.result.Status,
		PolicyReceipt:       cloneSignedPolicyReceipt(receipt),
		Reason:              strings.TrimSpace(lifecycle.Reason),
		Metadata:            transitionMetadata,
		OccurredAt:          receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) transitionThreadDecisionState(
	ctx context.Context,
	cellID string,
	sessionID string,
	threadID string,
	decisionID string,
	lifecycle SecureCellLifecycleRequest,
	stage string,
	targetStatus SecureCellThreadDecisionStatus,
	recordAction string,
	allowedStatuses ...SecureCellThreadDecisionStatus,
) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	sessionIdx, session := findSecureCellSession(run.result.Sessions, sessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
	}
	if session.Status != SecureCellSessionStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: session %q is not active", ErrSessionNotActive, sessionID)
	}
	threadIdx, thread := findSecureCellThread(run.result.Threads, threadID)
	if thread == nil || thread.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrThreadNotFound, threadID)
	}
	if !threadStatusAllowed(thread.Status, SecureCellThreadStatusActive, SecureCellThreadStatusQuarantined) {
		return nil, fmt.Errorf("securecells/service: %w: thread %q cannot mutate decisions while %s", ErrThreadImmutable, threadID, thread.Status)
	}
	decisionIdx, decision := findSecureCellThreadDecision(run.result.Decisions, decisionID)
	if decision == nil || decision.ThreadID != thread.ID || decision.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrDecisionNotFound, decisionID)
	}
	if !decisionStatusAllowed(decision.Status, allowedStatuses...) {
		return nil, fmt.Errorf("securecells/service: %w: decision %q cannot transition from %s via %s", ErrDecisionImmutable, decisionID, decision.Status, stage)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellDecisionActorAllowed(run, *thread, *decision, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to mutate decision %q", ErrPolicyDenied, actorDID, decisionID)
	}

	transitionMetadata := cloneStringMap(lifecycle.Metadata)
	resumedStatus := targetStatus
	if stage == "resume_thread_decision" {
		resumedStatus = firstNonEmptyDecisionStatus(decision.QuarantinedFromStatus, SecureCellThreadDecisionStatusOpen)
	}
	receipt, err := s.evaluateStage(ctx, run.request, stage, lastReceiptHash(run.result), map[string]string{
		"session_id":             session.ID,
		"thread_id":              thread.ID,
		"decision_id":            decision.ID,
		"decision_title":         decision.Title,
		"decision_status_before": string(decision.Status),
		"decision_status_after":  string(resumedStatus),
		"thread_status_before":   string(thread.Status),
		"session_status_before":  string(session.Status),
		"cell_status_before":     string(run.result.Status),
		"transition_reason":      strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	statusBefore := decision.Status
	updatedAt := time.Now().UTC()
	run.result.Decisions[decisionIdx].Status = resumedStatus
	run.result.Decisions[decisionIdx].UpdatedAt = updatedAt
	switch stage {
	case "approve_thread_decision":
		run.result.Decisions[decisionIdx].ApprovedBy = actorDID
		run.result.Decisions[decisionIdx].ApprovedAt = &updatedAt
	case "quarantine_thread_decision":
		run.result.Decisions[decisionIdx].QuarantinedAt = &updatedAt
		run.result.Decisions[decisionIdx].ContainedBy = actorDID
		run.result.Decisions[decisionIdx].QuarantinedFromStatus = statusBefore
		if transitionMetadata == nil {
			transitionMetadata = make(map[string]string)
		}
		transitionMetadata["containment_mode"] = "thread_decision"
	case "resume_thread_decision":
		run.result.Decisions[decisionIdx].QuarantinedAt = nil
		run.result.Decisions[decisionIdx].ContainedBy = ""
		run.result.Decisions[decisionIdx].QuarantinedFromStatus = ""
	case "close_thread_decision":
		run.result.Decisions[decisionIdx].ClosedBy = actorDID
		run.result.Decisions[decisionIdx].ClosedAt = &updatedAt
	}
	run.result.Threads[threadIdx].UpdatedAt = updatedAt
	run.result.Sessions[sessionIdx].UpdatedAt = updatedAt
	run.result.UpdatedAt = updatedAt

	transition := SecureCellTransition{
		ID:                   transitionID(run.request, strings.TrimPrefix(recordAction, "secure_cell."), decision.ID),
		Action:               recordAction,
		Actor:                actorDID,
		TargetType:           "thread_decision",
		TargetDID:            decision.ID,
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		DecisionID:           decision.ID,
		SessionStatusBefore:  session.Status,
		SessionStatusAfter:   session.Status,
		ThreadStatusBefore:   thread.Status,
		ThreadStatusAfter:    thread.Status,
		DecisionStatusBefore: statusBefore,
		DecisionStatusAfter:  resumedStatus,
		CellStatusBefore:     run.result.Status,
		CellStatusAfter:      run.result.Status,
		PolicyReceipt:        cloneSignedPolicyReceipt(receipt),
		Reason:               strings.TrimSpace(lifecycle.Reason),
		Metadata:             transitionMetadata,
		OccurredAt:           receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// PauseSession pauses one room without pausing the parent secure cell.
func (s *Service) PauseSession(ctx context.Context, cellID string, sessionID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionSessionState(ctx, cellID, sessionID, lifecycle, "pause_session", SecureCellSessionStatusPaused, "secure_cell.session_paused", SecureCellSessionStatusActive)
}

// ResumeSession resumes one paused or quarantined session back to active
// collaboration.
func (s *Service) ResumeSession(ctx context.Context, cellID string, sessionID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionSessionState(ctx, cellID, sessionID, lifecycle, "resume_session", SecureCellSessionStatusActive, "secure_cell.session_resumed", SecureCellSessionStatusPaused, SecureCellSessionStatusQuarantined)
}

// QuarantineSession contains one session without freezing the parent secure
// cell.
func (s *Service) QuarantineSession(ctx context.Context, cellID string, sessionID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionSessionState(ctx, cellID, sessionID, lifecycle, "quarantine_session", SecureCellSessionStatusQuarantined, "secure_cell.session_quarantined", SecureCellSessionStatusActive, SecureCellSessionStatusPaused)
}

// CloseThread closes one collaboration stream inside an active session.
func (s *Service) CloseThread(ctx context.Context, cellID string, sessionID string, threadID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionThreadState(ctx, cellID, sessionID, threadID, lifecycle, "close_session_thread", SecureCellThreadStatusClosed, "secure_cell.session_thread_closed", SecureCellThreadStatusActive, SecureCellThreadStatusQuarantined)
}

// ResumeThread resumes one quarantined thread.
func (s *Service) ResumeThread(ctx context.Context, cellID string, sessionID string, threadID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionThreadState(ctx, cellID, sessionID, threadID, lifecycle, "resume_session_thread", SecureCellThreadStatusActive, "secure_cell.session_thread_resumed", SecureCellThreadStatusQuarantined)
}

// QuarantineThread contains one thread without freezing the whole session.
func (s *Service) QuarantineThread(ctx context.Context, cellID string, sessionID string, threadID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionThreadState(ctx, cellID, sessionID, threadID, lifecycle, "quarantine_session_thread", SecureCellThreadStatusQuarantined, "secure_cell.session_thread_quarantined", SecureCellThreadStatusActive)
}

func (s *Service) transitionThreadDecisionArtifacts(
	ctx context.Context,
	cellID string,
	sessionID string,
	threadID string,
	decisionID string,
	lifecycle SecureCellLifecycleRequest,
	stage string,
	recordAction string,
	targetStatus SecureCellArtifactContainmentStatus,
) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	sessionIdx, session := findSecureCellSession(run.result.Sessions, sessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
	}
	if session.Status != SecureCellSessionStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: session %q is not active", ErrSessionNotActive, sessionID)
	}
	threadIdx, thread := findSecureCellThread(run.result.Threads, threadID)
	if thread == nil || thread.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrThreadNotFound, threadID)
	}
	if !threadStatusAllowed(thread.Status, SecureCellThreadStatusActive, SecureCellThreadStatusQuarantined) {
		return nil, fmt.Errorf("securecells/service: %w: thread %q cannot mutate decision artifacts while %s", ErrThreadImmutable, threadID, thread.Status)
	}
	decisionIdx, decision := findSecureCellThreadDecision(run.result.Decisions, decisionID)
	if decision == nil || decision.ThreadID != thread.ID || decision.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrDecisionNotFound, decisionID)
	}
	if !decisionStatusAllowed(decision.Status, SecureCellThreadDecisionStatusOpen, SecureCellThreadDecisionStatusApproved, SecureCellThreadDecisionStatusQuarantined, SecureCellThreadDecisionStatusQuorumFailed) {
		return nil, fmt.Errorf("securecells/service: %w: decision %q cannot mutate related artifacts while %s", ErrDecisionImmutable, decisionID, decision.Status)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellDecisionActorAllowed(run, *thread, *decision, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to mutate decision %q artifacts", ErrPolicyDenied, actorDID, decisionID)
	}

	outputIdxs := make([]int, 0, len(decision.RelatedOutputIDs))
	exchangeIdxs := make([]int, 0, len(decision.RelatedExchangeIDs))
	for _, outputID := range decision.RelatedOutputIDs {
		idx := findSecureCellSharedOutputIndex(run.result.SharedOutputs, outputID)
		if idx < 0 || run.result.SharedOutputs[idx].SessionID != session.ID {
			continue
		}
		output := run.result.SharedOutputs[idx]
		if targetStatus == SecureCellArtifactContainmentStatusContained && output.ContainmentStatus == SecureCellArtifactContainmentStatusContained && output.ContainmentDecisionID != "" && output.ContainmentDecisionID != decision.ID {
			return nil, fmt.Errorf("securecells/service: %w: shared output %q is already contained by decision %q", ErrDecisionImmutable, outputID, output.ContainmentDecisionID)
		}
		if targetStatus == SecureCellArtifactContainmentStatusReleased && !(output.ContainmentStatus == SecureCellArtifactContainmentStatusContained && output.ContainmentDecisionID == decision.ID) {
			continue
		}
		outputIdxs = append(outputIdxs, idx)
	}
	for _, exchangeID := range decision.RelatedExchangeIDs {
		idx := findSecureCellSessionExchangeIndex(run.result.SessionExchanges, exchangeID)
		if idx < 0 || run.result.SessionExchanges[idx].SessionID != session.ID || run.result.SessionExchanges[idx].ThreadID != thread.ID {
			continue
		}
		item := run.result.SessionExchanges[idx]
		if targetStatus == SecureCellArtifactContainmentStatusContained && item.ContainmentStatus == SecureCellArtifactContainmentStatusContained && item.ContainmentDecisionID != "" && item.ContainmentDecisionID != decision.ID {
			return nil, fmt.Errorf("securecells/service: %w: session exchange %q is already contained by decision %q", ErrDecisionImmutable, exchangeID, item.ContainmentDecisionID)
		}
		if targetStatus == SecureCellArtifactContainmentStatusReleased && !(item.ContainmentStatus == SecureCellArtifactContainmentStatusContained && item.ContainmentDecisionID == decision.ID) {
			continue
		}
		exchangeIdxs = append(exchangeIdxs, idx)
	}
	if len(outputIdxs) == 0 && len(exchangeIdxs) == 0 {
		return nil, fmt.Errorf("securecells/service: %w: decision %q has no related artifacts eligible for %s", ErrDecisionImmutable, decisionID, stage)
	}

	receipt, err := s.evaluateStage(ctx, run.request, stage, lastReceiptHash(run.result), map[string]string{
		"session_id":                       session.ID,
		"thread_id":                        thread.ID,
		"decision_id":                      decision.ID,
		"decision_title":                   decision.Title,
		"decision_status_before":           string(decision.Status),
		"decision_artifact_action":         string(targetStatus),
		"decision_related_outputs_total":   fmt.Sprintf("%d", len(outputIdxs)),
		"decision_related_exchanges_total": fmt.Sprintf("%d", len(exchangeIdxs)),
		"decision_related_output_ids":      strings.Join(decision.RelatedOutputIDs, ","),
		"decision_related_exchange_ids":    strings.Join(decision.RelatedExchangeIDs, ","),
		"thread_status_before":             string(thread.Status),
		"session_status_before":            string(session.Status),
		"cell_status_before":               string(run.result.Status),
		"transition_reason":                strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	updatedAt := time.Now().UTC()
	outputIDs := make([]string, 0, len(outputIdxs))
	exchangeIDs := make([]string, 0, len(exchangeIdxs))
	for _, idx := range outputIdxs {
		run.result.SharedOutputs[idx].ContainmentStatus = targetStatus
		run.result.SharedOutputs[idx].ContainmentDecisionID = decision.ID
		run.result.SharedOutputs[idx].ContainmentSourceType = "decision"
		run.result.SharedOutputs[idx].ContainmentSourceID = decision.ID
		run.result.SharedOutputs[idx].ContainmentReceiptID = receipt.ID
		run.result.SharedOutputs[idx].ContainmentReceiptHash = receipt.ContentHash
		run.result.SharedOutputs[idx].ContainmentSealID = ""
		run.result.SharedOutputs[idx].ContainmentTraceLinkID = ""
		if targetStatus == SecureCellArtifactContainmentStatusContained {
			run.result.SharedOutputs[idx].ContainedBy = actorDID
			run.result.SharedOutputs[idx].ContainedAt = &updatedAt
			run.result.SharedOutputs[idx].ReleasedBy = ""
			run.result.SharedOutputs[idx].ReleasedAt = nil
		} else {
			run.result.SharedOutputs[idx].ReleasedBy = actorDID
			run.result.SharedOutputs[idx].ReleasedAt = &updatedAt
		}
		outputIDs = append(outputIDs, run.result.SharedOutputs[idx].ID)
	}
	for _, idx := range exchangeIdxs {
		run.result.SessionExchanges[idx].ContainmentStatus = targetStatus
		run.result.SessionExchanges[idx].ContainmentDecisionID = decision.ID
		run.result.SessionExchanges[idx].ContainmentSourceType = "decision"
		run.result.SessionExchanges[idx].ContainmentSourceID = decision.ID
		run.result.SessionExchanges[idx].ContainmentReceiptID = receipt.ID
		run.result.SessionExchanges[idx].ContainmentReceiptHash = receipt.ContentHash
		run.result.SessionExchanges[idx].ContainmentSealID = ""
		run.result.SessionExchanges[idx].ContainmentTraceLinkID = ""
		if targetStatus == SecureCellArtifactContainmentStatusContained {
			run.result.SessionExchanges[idx].ContainedBy = actorDID
			run.result.SessionExchanges[idx].ContainedAt = &updatedAt
			run.result.SessionExchanges[idx].ReleasedBy = ""
			run.result.SessionExchanges[idx].ReleasedAt = nil
		} else {
			run.result.SessionExchanges[idx].ReleasedBy = actorDID
			run.result.SessionExchanges[idx].ReleasedAt = &updatedAt
		}
		exchangeIDs = append(exchangeIDs, run.result.SessionExchanges[idx].ID)
	}
	run.result.Decisions[decisionIdx].UpdatedAt = updatedAt
	run.result.Threads[threadIdx].UpdatedAt = updatedAt
	run.result.Sessions[sessionIdx].UpdatedAt = updatedAt
	run.result.UpdatedAt = updatedAt

	transitionMetadata := cloneStringMap(lifecycle.Metadata)
	if transitionMetadata == nil {
		transitionMetadata = make(map[string]string)
	}
	transitionMetadata["decision_output_ids"] = strings.Join(outputIDs, ",")
	transitionMetadata["decision_exchange_ids"] = strings.Join(exchangeIDs, ",")
	transitionMetadata["decision_output_count"] = fmt.Sprintf("%d", len(outputIDs))
	transitionMetadata["decision_exchange_count"] = fmt.Sprintf("%d", len(exchangeIDs))
	transitionMetadata["containment_mode"] = "thread_decision_artifacts"
	transitionMetadata["containment_status"] = string(targetStatus)

	transition := SecureCellTransition{
		ID:                   transitionID(run.request, strings.TrimPrefix(recordAction, "secure_cell."), decision.ID+"-"+string(targetStatus)),
		Action:               recordAction,
		Actor:                actorDID,
		TargetType:           "thread_decision_artifacts",
		TargetDID:            decision.ID,
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		DecisionID:           decision.ID,
		SessionStatusBefore:  session.Status,
		SessionStatusAfter:   session.Status,
		ThreadStatusBefore:   thread.Status,
		ThreadStatusAfter:    thread.Status,
		DecisionStatusBefore: decision.Status,
		DecisionStatusAfter:  decision.Status,
		CellStatusBefore:     run.result.Status,
		CellStatusAfter:      run.result.Status,
		PolicyReceipt:        cloneSignedPolicyReceipt(receipt),
		Reason:               strings.TrimSpace(lifecycle.Reason),
		Metadata:             transitionMetadata,
		OccurredAt:           receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	if lastTransition := lastSecureCellTransition(run.result); lastTransition != nil && lastTransition.DecisionID == decision.ID && lastTransition.Action == recordAction {
		for _, idx := range outputIdxs {
			run.result.SharedOutputs[idx].ContainmentSealID = safeString(lastTransition.ExecutionSeal, func(in *evidence.Seal) string { return in.SealID })
			run.result.SharedOutputs[idx].ContainmentTraceLinkID = safeString(lastTransition.TraceLink, func(in *evidence.TraceLink) string { return in.ID })
		}
		for _, idx := range exchangeIdxs {
			run.result.SessionExchanges[idx].ContainmentSealID = safeString(lastTransition.ExecutionSeal, func(in *evidence.Seal) string { return in.SealID })
			run.result.SessionExchanges[idx].ContainmentTraceLinkID = safeString(lastTransition.TraceLink, func(in *evidence.TraceLink) string { return in.ID })
		}
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) voteThreadDecision(
	ctx context.Context,
	cellID string,
	sessionID string,
	threadID string,
	decisionID string,
	lifecycle SecureCellLifecycleRequest,
	choice SecureCellThreadDecisionVoteChoice,
) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	sessionIdx, session := findSecureCellSession(run.result.Sessions, sessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
	}
	if session.Status != SecureCellSessionStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: session %q is not active", ErrSessionNotActive, sessionID)
	}
	threadIdx, thread := findSecureCellThread(run.result.Threads, threadID)
	if thread == nil || thread.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrThreadNotFound, threadID)
	}
	if thread.Status != SecureCellThreadStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: thread %q is not active", ErrThreadNotActive, threadID)
	}
	decisionIdx, decision := findSecureCellThreadDecision(run.result.Decisions, decisionID)
	if decision == nil || decision.ThreadID != thread.ID || decision.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrDecisionNotFound, decisionID)
	}
	if decision.Status != SecureCellThreadDecisionStatusOpen {
		return nil, fmt.Errorf("securecells/service: %w: decision %q cannot accept votes while %s", ErrDecisionImmutable, decisionID, decision.Status)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellDecisionActorAllowed(run, *thread, *decision, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to mutate decision %q", ErrPolicyDenied, actorDID, decisionID)
	}
	if !secureCellDecisionApproverAllowed(run, *thread, *decision, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not an eligible approver for decision %q", ErrPolicyDenied, actorDID, decisionID)
	}
	if secureCellDecisionHasApprovalVote(*decision, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q already voted on decision %q", ErrDecisionImmutable, actorDID, decisionID)
	}

	threshold := decisionApprovalThreshold(*decision)
	votesBefore := len(decision.ApprovalVotes)
	actorRole := secureCellActorRole(run, actorDID)
	if !secureCellDecisionVoteChoiceEnabled(*decision, choice) {
		return nil, fmt.Errorf("securecells/service: %w: vote choice %q is not permitted for decision %q", ErrPolicyDenied, choice, decisionID)
	}
	switch choice {
	case SecureCellThreadDecisionVoteChoiceReject:
		if !secureCellDecisionRoleRuleAllows(actorRole, decision.RejectorRoles) {
			return nil, fmt.Errorf("securecells/service: %w: actor %q with role %q cannot reject decision %q", ErrPolicyDenied, actorDID, actorRole, decisionID)
		}
	case SecureCellThreadDecisionVoteChoiceAbstain:
		if !secureCellDecisionRoleRuleAllows(actorRole, decision.AbstainerRoles) {
			return nil, fmt.Errorf("securecells/service: %w: actor %q with role %q cannot abstain on decision %q", ErrPolicyDenied, actorDID, actorRole, decisionID)
		}
	}
	votesAfter := votesBefore + 1
	receipt, err := s.evaluateStage(ctx, run.request, "approve_thread_decision", lastReceiptHash(run.result), map[string]string{
		"session_id":                  session.ID,
		"thread_id":                   thread.ID,
		"decision_id":                 decision.ID,
		"decision_title":              decision.Title,
		"decision_status_before":      string(decision.Status),
		"decision_status_after":       string(decision.Status),
		"decision_vote_choice":        string(choice),
		"decision_approval_threshold": fmt.Sprintf("%d", threshold),
		"decision_votes_before":       fmt.Sprintf("%d", votesBefore),
		"decision_votes_after":        fmt.Sprintf("%d", votesAfter),
		"decision_eligible_approvers": strings.Join(decision.EligibleApproverDIDs, ","),
		"decision_required_roles":     strings.Join(decision.RequiredApproverRoles, ","),
		"decision_actor_role":         actorRole,
		"thread_status_before":        string(thread.Status),
		"session_status_before":       string(session.Status),
		"cell_status_before":          string(run.result.Status),
		"transition_reason":           strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	updatedAt := time.Now().UTC()
	vote := SecureCellThreadDecisionVote{
		ID:                secureCellThreadDecisionVoteID(run.request, *decision, actorDID, votesBefore),
		DecisionID:        decision.ID,
		ActorDID:          actorDID,
		ActorRole:         actorRole,
		Choice:            choice,
		Reason:            strings.TrimSpace(lifecycle.Reason),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		CreatedAt:         updatedAt,
		Metadata:          cloneStringMap(lifecycle.Metadata),
	}
	run.result.Decisions[decisionIdx].ApprovalVotes = append(run.result.Decisions[decisionIdx].ApprovalVotes, vote)

	statusBefore := decision.Status
	statusAfter := statusBefore
	recordAction := "secure_cell.session_thread_decision_voted"
	transitionMetadata := cloneStringMap(lifecycle.Metadata)
	if transitionMetadata == nil {
		transitionMetadata = make(map[string]string)
	}
	transitionMetadata["approval_vote_id"] = vote.ID
	transitionMetadata["approval_vote_actor_role"] = vote.ActorRole
	transitionMetadata["approval_vote_choice"] = string(vote.Choice)
	transitionMetadata["approval_threshold"] = fmt.Sprintf("%d", threshold)
	transitionMetadata["approval_votes_total"] = fmt.Sprintf("%d", len(run.result.Decisions[decisionIdx].ApprovalVotes))
	transitionMetadata["required_roles_remaining"] = strings.Join(secureCellDecisionMissingRequiredRoles(run.result.Decisions[decisionIdx]), ",")

	if secureCellDecisionApprovalSatisfied(run.result.Decisions[decisionIdx]) {
		statusAfter = SecureCellThreadDecisionStatusApproved
		recordAction = "secure_cell.session_thread_decision_approved"
		run.result.Decisions[decisionIdx].ApprovedBy = actorDID
		run.result.Decisions[decisionIdx].ApprovedAt = &updatedAt
		run.result.Decisions[decisionIdx].QuorumFailedBy = ""
		run.result.Decisions[decisionIdx].QuorumFailedAt = nil
		transitionMetadata["approval_threshold_satisfied"] = "true"
		transitionMetadata["approval_quorum_reachable"] = "true"
	} else if !secureCellDecisionApprovalReachable(run, *thread, run.result.Decisions[decisionIdx]) {
		statusAfter = SecureCellThreadDecisionStatusQuorumFailed
		recordAction = "secure_cell.session_thread_decision_quorum_failed"
		run.result.Decisions[decisionIdx].QuorumFailedBy = actorDID
		run.result.Decisions[decisionIdx].QuorumFailedAt = &updatedAt
		transitionMetadata["approval_threshold_satisfied"] = "false"
		transitionMetadata["approval_quorum_reachable"] = "false"
	} else {
		transitionMetadata["approval_threshold_satisfied"] = "false"
		transitionMetadata["approval_quorum_reachable"] = "true"
	}

	run.result.Decisions[decisionIdx].Status = statusAfter
	run.result.Decisions[decisionIdx].UpdatedAt = updatedAt
	run.result.Threads[threadIdx].UpdatedAt = updatedAt
	run.result.Sessions[sessionIdx].UpdatedAt = updatedAt
	run.result.UpdatedAt = updatedAt

	transition := SecureCellTransition{
		ID:                   transitionID(run.request, strings.TrimPrefix(recordAction, "secure_cell."), vote.ID),
		Action:               recordAction,
		Actor:                actorDID,
		TargetType:           "thread_decision",
		TargetDID:            decision.ID,
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		DecisionID:           decision.ID,
		SessionStatusBefore:  session.Status,
		SessionStatusAfter:   session.Status,
		ThreadStatusBefore:   thread.Status,
		ThreadStatusAfter:    thread.Status,
		DecisionStatusBefore: statusBefore,
		DecisionStatusAfter:  statusAfter,
		CellStatusBefore:     run.result.Status,
		CellStatusAfter:      run.result.Status,
		PolicyReceipt:        cloneSignedPolicyReceipt(receipt),
		Reason:               strings.TrimSpace(lifecycle.Reason),
		Metadata:             transitionMetadata,
		OccurredAt:           receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	if lastTransition := lastSecureCellTransition(run.result); lastTransition != nil && lastTransition.DecisionID == decision.ID && lastTransition.Action == recordAction {
		lastVoteIdx := len(run.result.Decisions[decisionIdx].ApprovalVotes) - 1
		run.result.Decisions[decisionIdx].ApprovalVotes[lastVoteIdx].SealID = safeString(lastTransition.ExecutionSeal, func(in *evidence.Seal) string { return in.SealID })
		run.result.Decisions[decisionIdx].ApprovalVotes[lastVoteIdx].TraceLinkID = safeString(lastTransition.TraceLink, func(in *evidence.TraceLink) string { return in.ID })
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// VoteThreadDecision records one governed decision vote with an explicit
// approve, reject, or abstain choice.
func (s *Service) VoteThreadDecision(ctx context.Context, cellID string, sessionID string, threadID string, decisionID string, lifecycle SecureCellLifecycleRequest, choice SecureCellThreadDecisionVoteChoice) (*SecureCellResult, error) {
	return s.voteThreadDecision(ctx, cellID, sessionID, threadID, decisionID, lifecycle, choice)
}

// ApproveThreadDecision records one approval vote and only marks the decision
// approved once its threshold and required-role quorum are both satisfied.
func (s *Service) ApproveThreadDecision(ctx context.Context, cellID string, sessionID string, threadID string, decisionID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.VoteThreadDecision(ctx, cellID, sessionID, threadID, decisionID, lifecycle, SecureCellThreadDecisionVoteChoiceApprove)
}

// RejectThreadDecision records one explicit reject vote and may mark the
// decision quorum-failed if approval is no longer reachable.
func (s *Service) RejectThreadDecision(ctx context.Context, cellID string, sessionID string, threadID string, decisionID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.VoteThreadDecision(ctx, cellID, sessionID, threadID, decisionID, lifecycle, SecureCellThreadDecisionVoteChoiceReject)
}

// AbstainThreadDecision records one abstain vote and preserves the decision
// unless approval quorum becomes unreachable.
func (s *Service) AbstainThreadDecision(ctx context.Context, cellID string, sessionID string, threadID string, decisionID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.VoteThreadDecision(ctx, cellID, sessionID, threadID, decisionID, lifecycle, SecureCellThreadDecisionVoteChoiceAbstain)
}

// CommentThreadDecision records one evidence-bearing decision comment.
func (s *Service) CommentThreadDecision(ctx context.Context, cellID string, sessionID string, threadID string, decisionID string, req SecureCellThreadDecisionCommentRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	sessionIdx, session := findSecureCellSession(run.result.Sessions, sessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
	}
	if session.Status != SecureCellSessionStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: session %q is not active", ErrSessionNotActive, sessionID)
	}
	threadIdx, thread := findSecureCellThread(run.result.Threads, threadID)
	if thread == nil || thread.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrThreadNotFound, threadID)
	}
	if thread.Status != SecureCellThreadStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: thread %q is not active", ErrThreadNotActive, threadID)
	}
	decisionIdx, decision := findSecureCellThreadDecision(run.result.Decisions, decisionID)
	if decision == nil || decision.ThreadID != thread.ID || decision.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrDecisionNotFound, decisionID)
	}
	if !decisionStatusAllowed(decision.Status, SecureCellThreadDecisionStatusOpen, SecureCellThreadDecisionStatusApproved, SecureCellThreadDecisionStatusQuorumFailed) {
		return nil, fmt.Errorf("securecells/service: %w: decision %q cannot be commented on while %s", ErrDecisionImmutable, decisionID, decision.Status)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellDecisionActorAllowed(run, *thread, *decision, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to comment on decision %q", ErrPolicyDenied, actorDID, decisionID)
	}
	actorRole := secureCellActorRole(run, actorDID)
	commentText := strings.TrimSpace(req.Comment)
	if commentText == "" {
		return nil, fmt.Errorf("securecells/service: decision comment is required")
	}

	receipt, err := s.evaluateStage(ctx, run.request, "comment_thread_decision", lastReceiptHash(run.result), map[string]string{
		"session_id":                    session.ID,
		"thread_id":                     thread.ID,
		"decision_id":                   decision.ID,
		"decision_title":                decision.Title,
		"decision_status_before":        string(decision.Status),
		"decision_status_after":         string(decision.Status),
		"decision_comment_length":       fmt.Sprintf("%d", len(commentText)),
		"decision_comment_count_before": fmt.Sprintf("%d", len(decision.Comments)),
		"decision_comment_count_after":  fmt.Sprintf("%d", len(decision.Comments)+1),
		"thread_status_before":          string(thread.Status),
		"session_status_before":         string(session.Status),
		"cell_status_before":            string(run.result.Status),
		"transition_reason":             strings.TrimSpace(req.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	updatedAt := time.Now().UTC()
	comment := SecureCellThreadDecisionComment{
		ID:                secureCellThreadDecisionCommentID(run.request, *decision, actorDID, commentText, len(decision.Comments)),
		DecisionID:        decision.ID,
		ActorDID:          actorDID,
		ActorRole:         actorRole,
		Comment:           commentText,
		Reason:            strings.TrimSpace(req.Reason),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		CreatedAt:         updatedAt,
		Metadata:          cloneStringMap(req.Metadata),
	}
	run.result.Decisions[decisionIdx].Comments = append(run.result.Decisions[decisionIdx].Comments, comment)
	run.result.Decisions[decisionIdx].UpdatedAt = updatedAt
	run.result.Threads[threadIdx].UpdatedAt = updatedAt
	run.result.Sessions[sessionIdx].UpdatedAt = updatedAt
	run.result.UpdatedAt = updatedAt

	transitionMetadata := cloneStringMap(req.Metadata)
	if transitionMetadata == nil {
		transitionMetadata = make(map[string]string)
	}
	transitionMetadata["decision_comment_id"] = comment.ID
	transitionMetadata["decision_comment_count"] = fmt.Sprintf("%d", len(run.result.Decisions[decisionIdx].Comments))
	transitionMetadata["decision_comment_actor_role"] = actorRole

	transition := SecureCellTransition{
		ID:                   transitionID(run.request, "session_thread_decision_commented", comment.ID),
		Action:               "secure_cell.session_thread_decision_commented",
		Actor:                actorDID,
		TargetType:           "thread_decision",
		TargetDID:            decision.ID,
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		DecisionID:           decision.ID,
		SessionStatusBefore:  session.Status,
		SessionStatusAfter:   session.Status,
		ThreadStatusBefore:   thread.Status,
		ThreadStatusAfter:    thread.Status,
		DecisionStatusBefore: decision.Status,
		DecisionStatusAfter:  decision.Status,
		CellStatusBefore:     run.result.Status,
		CellStatusAfter:      run.result.Status,
		PolicyReceipt:        cloneSignedPolicyReceipt(receipt),
		Reason:               strings.TrimSpace(req.Reason),
		Metadata:             transitionMetadata,
		OccurredAt:           receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	if lastTransition := lastSecureCellTransition(run.result); lastTransition != nil && lastTransition.DecisionID == decision.ID && lastTransition.Action == "secure_cell.session_thread_decision_commented" {
		lastCommentIdx := len(run.result.Decisions[decisionIdx].Comments) - 1
		run.result.Decisions[decisionIdx].Comments[lastCommentIdx].SealID = safeString(lastTransition.ExecutionSeal, func(in *evidence.Seal) string { return in.SealID })
		run.result.Decisions[decisionIdx].Comments[lastCommentIdx].TraceLinkID = safeString(lastTransition.TraceLink, func(in *evidence.TraceLink) string { return in.ID })
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// DelegateThreadDecision broadens one governed decision flow to another actor
// without changing the entire thread's membership.
func (s *Service) DelegateThreadDecision(ctx context.Context, cellID string, sessionID string, threadID string, decisionID string, req SecureCellThreadDecisionDelegationRequest) (*SecureCellResult, error) {
	return s.routeThreadDecision(ctx, cellID, sessionID, threadID, decisionID, req, SecureCellThreadDecisionDelegationModeDelegate, "delegate_thread_decision", "secure_cell.session_thread_decision_delegated")
}

// EscalateThreadDecision explicitly escalates one governed decision flow to a
// new actor who may not already be part of the thread.
func (s *Service) EscalateThreadDecision(ctx context.Context, cellID string, sessionID string, threadID string, decisionID string, req SecureCellThreadDecisionDelegationRequest) (*SecureCellResult, error) {
	return s.routeThreadDecision(ctx, cellID, sessionID, threadID, decisionID, req, SecureCellThreadDecisionDelegationModeEscalate, "escalate_thread_decision", "secure_cell.session_thread_decision_escalated")
}

func (s *Service) routeThreadDecision(
	ctx context.Context,
	cellID string,
	sessionID string,
	threadID string,
	decisionID string,
	req SecureCellThreadDecisionDelegationRequest,
	mode SecureCellThreadDecisionDelegationMode,
	stage string,
	recordAction string,
) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	sessionIdx, session := findSecureCellSession(run.result.Sessions, sessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
	}
	if session.Status != SecureCellSessionStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: session %q is not active", ErrSessionNotActive, sessionID)
	}
	threadIdx, thread := findSecureCellThread(run.result.Threads, threadID)
	if thread == nil || thread.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrThreadNotFound, threadID)
	}
	if thread.Status != SecureCellThreadStatusActive {
		return nil, fmt.Errorf("securecells/service: %w: thread %q is not active", ErrThreadNotActive, threadID)
	}
	decisionIdx, decision := findSecureCellThreadDecision(run.result.Decisions, decisionID)
	if decision == nil || decision.ThreadID != thread.ID || decision.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrDecisionNotFound, decisionID)
	}
	if !decisionStatusAllowed(decision.Status, SecureCellThreadDecisionStatusOpen, SecureCellThreadDecisionStatusApproved, SecureCellThreadDecisionStatusQuorumFailed) {
		return nil, fmt.Errorf("securecells/service: %w: decision %q cannot route actors while %s", ErrDecisionImmutable, decisionID, decision.Status)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellDecisionActorAllowed(run, *thread, *decision, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to route decision %q", ErrPolicyDenied, actorDID, decisionID)
	}
	targetDID := strings.TrimSpace(req.TargetDID)
	if targetDID == "" {
		return nil, fmt.Errorf("securecells/service: decision routing target is required")
	}
	if !secureCellDecisionParticipantAllowed(run, targetDID) {
		return nil, fmt.Errorf("securecells/service: %w: target actor %q is not an active secure-cell participant", ErrPolicyDenied, targetDID)
	}
	if secureCellDecisionHasDelegation(*decision, mode, targetDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is already %s for decision %q", ErrDecisionImmutable, targetDID, mode, decisionID)
	}

	actorRole := secureCellActorRole(run, actorDID)
	targetRole := secureCellActorRole(run, targetDID)
	if decision.Status == SecureCellThreadDecisionStatusQuorumFailed && !secureCellDecisionRoleRuleAllows(actorRole, decision.ReopenRoles) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q with role %q cannot reopen decision %q", ErrPolicyDenied, actorDID, actorRole, decisionID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, stage, lastReceiptHash(run.result), map[string]string{
		"session_id":              session.ID,
		"thread_id":               thread.ID,
		"decision_id":             decision.ID,
		"decision_title":          decision.Title,
		"decision_status_before":  string(decision.Status),
		"decision_route_mode":     string(mode),
		"decision_route_target":   targetDID,
		"decision_route_role":     targetRole,
		"decision_required_roles": strings.Join(decision.RequiredApproverRoles, ","),
		"thread_status_before":    string(thread.Status),
		"session_status_before":   string(session.Status),
		"cell_status_before":      string(run.result.Status),
		"transition_reason":       strings.TrimSpace(req.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	updatedAt := time.Now().UTC()
	delegation := SecureCellThreadDecisionDelegation{
		ID:                secureCellThreadDecisionDelegationID(run.request, *decision, mode, actorDID, targetDID, len(decision.Delegations)),
		DecisionID:        decision.ID,
		FromActorDID:      actorDID,
		FromActorRole:     actorRole,
		ToActorDID:        targetDID,
		ToActorRole:       targetRole,
		Mode:              mode,
		Reason:            strings.TrimSpace(req.Reason),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		CreatedAt:         updatedAt,
		Metadata:          cloneStringMap(req.Metadata),
	}
	run.result.Decisions[decisionIdx].Delegations = append(run.result.Decisions[decisionIdx].Delegations, delegation)
	run.result.Decisions[decisionIdx].EligibleApproverDIDs = uniqueSecureCellStrings(append(run.result.Decisions[decisionIdx].EligibleApproverDIDs, targetDID))
	statusBefore := decision.Status
	statusAfter := decision.Status
	if decision.Status == SecureCellThreadDecisionStatusQuorumFailed && secureCellDecisionApprovalReachable(run, *thread, run.result.Decisions[decisionIdx]) {
		statusAfter = SecureCellThreadDecisionStatusOpen
		run.result.Decisions[decisionIdx].Status = statusAfter
		run.result.Decisions[decisionIdx].QuorumFailedBy = ""
		run.result.Decisions[decisionIdx].QuorumFailedAt = nil
	}
	run.result.Decisions[decisionIdx].UpdatedAt = updatedAt
	run.result.Threads[threadIdx].UpdatedAt = updatedAt
	run.result.Sessions[sessionIdx].UpdatedAt = updatedAt
	run.result.UpdatedAt = updatedAt

	transitionMetadata := cloneStringMap(req.Metadata)
	if transitionMetadata == nil {
		transitionMetadata = make(map[string]string)
	}
	transitionMetadata["decision_delegation_id"] = delegation.ID
	transitionMetadata["decision_route_mode"] = string(mode)
	transitionMetadata["decision_route_target"] = targetDID
	transitionMetadata["decision_route_role"] = targetRole
	transitionMetadata["decision_delegations_total"] = fmt.Sprintf("%d", len(run.result.Decisions[decisionIdx].Delegations))
	transitionMetadata["decision_quorum_reopened"] = strconv.FormatBool(statusBefore == SecureCellThreadDecisionStatusQuorumFailed && statusAfter == SecureCellThreadDecisionStatusOpen)

	transition := SecureCellTransition{
		ID:                   transitionID(run.request, strings.TrimPrefix(recordAction, "secure_cell."), delegation.ID),
		Action:               recordAction,
		Actor:                actorDID,
		TargetType:           "thread_decision",
		TargetDID:            decision.ID,
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		DecisionID:           decision.ID,
		SessionStatusBefore:  session.Status,
		SessionStatusAfter:   session.Status,
		ThreadStatusBefore:   thread.Status,
		ThreadStatusAfter:    thread.Status,
		DecisionStatusBefore: statusBefore,
		DecisionStatusAfter:  statusAfter,
		CellStatusBefore:     run.result.Status,
		CellStatusAfter:      run.result.Status,
		PolicyReceipt:        cloneSignedPolicyReceipt(receipt),
		Reason:               strings.TrimSpace(req.Reason),
		Metadata:             transitionMetadata,
		OccurredAt:           receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	if lastTransition := lastSecureCellTransition(run.result); lastTransition != nil && lastTransition.DecisionID == decision.ID && lastTransition.Action == recordAction {
		lastDelegationIdx := len(run.result.Decisions[decisionIdx].Delegations) - 1
		run.result.Decisions[decisionIdx].Delegations[lastDelegationIdx].SealID = safeString(lastTransition.ExecutionSeal, func(in *evidence.Seal) string { return in.SealID })
		run.result.Decisions[decisionIdx].Delegations[lastDelegationIdx].TraceLinkID = safeString(lastTransition.TraceLink, func(in *evidence.TraceLink) string { return in.ID })
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// PublishThreadDecisionOutcome creates one portable outcome bundle tied to a
// governed decision and its selected artifacts.
func (s *Service) PublishThreadDecisionOutcome(ctx context.Context, cellID string, sessionID string, threadID string, decisionID string, req SecureCellThreadDecisionOutcomeRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	sessionIdx, session := findSecureCellSession(run.result.Sessions, sessionID)
	if session == nil {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrSessionNotFound, sessionID)
	}
	threadIdx, thread := findSecureCellThread(run.result.Threads, threadID)
	if thread == nil || thread.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrThreadNotFound, threadID)
	}
	decisionIdx, decision := findSecureCellThreadDecision(run.result.Decisions, decisionID)
	if decision == nil || decision.ThreadID != thread.ID || decision.SessionID != session.ID {
		return nil, fmt.Errorf("securecells/service: %w: %q", ErrDecisionNotFound, decisionID)
	}
	if !decisionStatusAllowed(decision.Status, SecureCellThreadDecisionStatusApproved, SecureCellThreadDecisionStatusClosed) {
		return nil, fmt.Errorf("securecells/service: %w: decision %q cannot publish outcomes while %s", ErrDecisionImmutable, decisionID, decision.Status)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellDecisionActorAllowed(run, *thread, *decision, actorDID) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to publish outcomes for decision %q", ErrPolicyDenied, actorDID, decisionID)
	}
	actorRole := secureCellActorRole(run, actorDID)
	classification, err := secureCellResolveThreadDecisionClassification(*thread, req.Classification)
	if err != nil {
		return nil, err
	}
	relatedExchangeIDs, err := secureCellResolveThreadDecisionExchangeRefs(*session, *thread, run.result.SessionExchanges, firstNonEmptyDecisionRefs(req.RelatedExchangeIDs, decision.RelatedExchangeIDs))
	if err != nil {
		return nil, err
	}
	relatedOutputIDs, err := secureCellResolveThreadDecisionOutputRefs(*session, run.result.SharedOutputs, firstNonEmptyDecisionRefs(req.RelatedOutputIDs, decision.RelatedOutputIDs))
	if err != nil {
		return nil, err
	}
	title := firstNonEmpty(strings.TrimSpace(req.Title), decision.Title+" Outcome")
	outcomeType := firstNonEmpty(strings.TrimSpace(req.OutcomeType), "resolution_bundle")
	receipt, err := s.evaluateStage(ctx, run.request, "publish_thread_decision_outcome", lastReceiptHash(run.result), map[string]string{
		"session_id":                 session.ID,
		"thread_id":                  thread.ID,
		"decision_id":                decision.ID,
		"decision_title":             decision.Title,
		"decision_outcome_title":     title,
		"decision_outcome_type":      outcomeType,
		"decision_outcome_outputs":   strings.Join(relatedOutputIDs, ","),
		"decision_outcome_exchanges": strings.Join(relatedExchangeIDs, ","),
		"decision_required_roles":    strings.Join(decision.RequiredApproverRoles, ","),
		"thread_status_before":       string(thread.Status),
		"session_status_before":      string(session.Status),
		"cell_status_before":         string(run.result.Status),
		"transition_reason":          strings.TrimSpace(req.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	updatedAt := time.Now().UTC()
	outcome := SecureCellThreadDecisionOutcome{
		ID:                 secureCellThreadDecisionOutcomeID(run.request, *decision, title, actorDID, len(run.result.DecisionOutcomes)),
		DecisionID:         decision.ID,
		SessionID:          session.ID,
		ThreadID:           thread.ID,
		Title:              title,
		Summary:            strings.TrimSpace(req.Summary),
		Classification:     classification,
		OutcomeType:        outcomeType,
		PublishedBy:        actorDID,
		PublishedByRole:    actorRole,
		RelatedExchangeIDs: relatedExchangeIDs,
		RelatedOutputIDs:   relatedOutputIDs,
		IntegrityHash:      secureCellResolveThreadDecisionOutcomeIntegrityHash(req, *decision, title, classification, outcomeType, actorDID, relatedOutputIDs, relatedExchangeIDs),
		PolicyReceiptID:    receipt.ID,
		PolicyReceiptHash:  receipt.ContentHash,
		CreatedAt:          updatedAt,
		Metadata:           cloneStringMap(req.Metadata),
	}
	run.result.DecisionOutcomes = append(run.result.DecisionOutcomes, outcome)
	run.result.Decisions[decisionIdx].OutcomeIDs = append(run.result.Decisions[decisionIdx].OutcomeIDs, outcome.ID)
	run.result.Decisions[decisionIdx].UpdatedAt = updatedAt
	run.result.Threads[threadIdx].UpdatedAt = updatedAt
	run.result.Sessions[sessionIdx].UpdatedAt = updatedAt
	run.result.UpdatedAt = updatedAt

	transitionMetadata := cloneStringMap(req.Metadata)
	if transitionMetadata == nil {
		transitionMetadata = make(map[string]string)
	}
	transitionMetadata["decision_outcome_id"] = outcome.ID
	transitionMetadata["decision_outcome_type"] = outcome.OutcomeType
	transitionMetadata["decision_outcome_outputs"] = strings.Join(outcome.RelatedOutputIDs, ",")
	transitionMetadata["decision_outcome_exchanges"] = strings.Join(outcome.RelatedExchangeIDs, ",")
	transitionMetadata["decision_outcomes_total"] = fmt.Sprintf("%d", len(run.result.DecisionOutcomes))

	transition := SecureCellTransition{
		ID:                   transitionID(run.request, "session_thread_decision_outcome_published", outcome.ID),
		Action:               "secure_cell.session_thread_decision_outcome_published",
		Actor:                actorDID,
		TargetType:           "thread_decision_outcome",
		TargetDID:            outcome.ID,
		SessionID:            session.ID,
		ThreadID:             thread.ID,
		DecisionID:           decision.ID,
		SessionStatusBefore:  session.Status,
		SessionStatusAfter:   session.Status,
		ThreadStatusBefore:   thread.Status,
		ThreadStatusAfter:    thread.Status,
		DecisionStatusBefore: decision.Status,
		DecisionStatusAfter:  decision.Status,
		CellStatusBefore:     run.result.Status,
		CellStatusAfter:      run.result.Status,
		PolicyReceipt:        cloneSignedPolicyReceipt(receipt),
		Reason:               strings.TrimSpace(req.Reason),
		Metadata:             transitionMetadata,
		OccurredAt:           receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	if lastTransition := lastSecureCellTransition(run.result); lastTransition != nil && lastTransition.DecisionID == decision.ID && lastTransition.Action == "secure_cell.session_thread_decision_outcome_published" {
		lastOutcomeIdx := len(run.result.DecisionOutcomes) - 1
		run.result.DecisionOutcomes[lastOutcomeIdx].SealID = safeString(lastTransition.ExecutionSeal, func(in *evidence.Seal) string { return in.SealID })
		run.result.DecisionOutcomes[lastOutcomeIdx].TraceLinkID = safeString(lastTransition.TraceLink, func(in *evidence.TraceLink) string { return in.ID })
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// ContainThreadDecisionOutputs contains all decision-linked outputs and thread
// exchanges without freezing the whole thread.
func (s *Service) ContainThreadDecisionOutputs(ctx context.Context, cellID string, sessionID string, threadID string, decisionID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionThreadDecisionArtifacts(ctx, cellID, sessionID, threadID, decisionID, lifecycle, "contain_thread_decision_outputs", "secure_cell.session_thread_decision_outputs_contained", SecureCellArtifactContainmentStatusContained)
}

// ReleaseThreadDecisionOutputs releases all decision-linked outputs and thread
// exchanges previously contained by this decision.
func (s *Service) ReleaseThreadDecisionOutputs(ctx context.Context, cellID string, sessionID string, threadID string, decisionID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionThreadDecisionArtifacts(ctx, cellID, sessionID, threadID, decisionID, lifecycle, "release_thread_decision_outputs", "secure_cell.session_thread_decision_outputs_released", SecureCellArtifactContainmentStatusReleased)
}

// ResumeThreadDecision resumes one quarantined decision back to its last live status.
func (s *Service) ResumeThreadDecision(ctx context.Context, cellID string, sessionID string, threadID string, decisionID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionThreadDecisionState(ctx, cellID, sessionID, threadID, decisionID, lifecycle, "resume_thread_decision", SecureCellThreadDecisionStatusOpen, "secure_cell.session_thread_decision_resumed", SecureCellThreadDecisionStatusQuarantined)
}

// QuarantineThreadDecision contains one decision object without freezing the whole thread.
func (s *Service) QuarantineThreadDecision(ctx context.Context, cellID string, sessionID string, threadID string, decisionID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionThreadDecisionState(ctx, cellID, sessionID, threadID, decisionID, lifecycle, "quarantine_thread_decision", SecureCellThreadDecisionStatusQuarantined, "secure_cell.session_thread_decision_quarantined", SecureCellThreadDecisionStatusOpen, SecureCellThreadDecisionStatusApproved, SecureCellThreadDecisionStatusQuorumFailed)
}

// CloseThreadDecision closes one decision object while preserving its portable evidence.
func (s *Service) CloseThreadDecision(ctx context.Context, cellID string, sessionID string, threadID string, decisionID string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	return s.transitionThreadDecisionState(ctx, cellID, sessionID, threadID, decisionID, lifecycle, "close_thread_decision", SecureCellThreadDecisionStatusClosed, "secure_cell.session_thread_decision_closed", SecureCellThreadDecisionStatusOpen, SecureCellThreadDecisionStatusApproved, SecureCellThreadDecisionStatusQuarantined, SecureCellThreadDecisionStatusQuorumFailed)
}

// ListCells returns operator-facing summaries for the current secure-cell set.
func (s *Service) ListCells(_ context.Context, filter SecureCellListFilter) ([]SecureCellSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	statuses := make(map[SecureCellStatus]struct{}, len(filter.Statuses))
	for _, status := range filter.Statuses {
		if status == "" {
			continue
		}
		statuses[status] = struct{}{}
	}
	jurisdiction := strings.TrimSpace(filter.Jurisdiction)
	participantDID := strings.TrimSpace(filter.ParticipantDID)
	var summaries []SecureCellSummary
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if len(statuses) > 0 {
			if _, ok := statuses[run.result.Status]; !ok {
				continue
			}
		}
		if jurisdiction != "" && !strings.EqualFold(strings.TrimSpace(run.request.Jurisdiction), jurisdiction) {
			continue
		}
		if participantDID != "" && !secureCellHasParticipant(run.result.Participants, participantDID) {
			continue
		}
		if filter.UpdatedAfter != nil && run.result.UpdatedAt.Before(filter.UpdatedAfter.UTC()) {
			continue
		}
		if filter.UpdatedBefore != nil && run.result.UpdatedAt.After(filter.UpdatedBefore.UTC()) {
			continue
		}
		summaries = append(summaries, secureCellSummaryFromRun(run))
	}

	sort.SliceStable(summaries, func(i, j int) bool {
		if summaries[i].UpdatedAt.Equal(summaries[j].UpdatedAt) {
			return summaries[i].CreatedAt.After(summaries[j].CreatedAt)
		}
		return summaries[i].UpdatedAt.After(summaries[j].UpdatedAt)
	})
	if filter.Limit > 0 && len(summaries) > filter.Limit {
		summaries = summaries[:filter.Limit]
	}
	return summaries, nil
}

// ListExpiringQuarantines returns quarantined participants whose expiry is at
// or before the provided cutoff.
func (s *Service) ListExpiringQuarantines(_ context.Context, before time.Time) ([]SecureCellQuarantineExpiry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if before.IsZero() {
		before = time.Now().UTC()
	}
	var items []SecureCellQuarantineExpiry
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		for _, participant := range run.result.Participants {
			if participant.Status != SecureCellParticipantStatusQuarantined || participant.QuarantineExpiresAt == nil {
				continue
			}
			if participant.QuarantineExpiresAt.After(before) {
				continue
			}
			items = append(items, SecureCellQuarantineExpiry{
				CellID:         run.result.CellID,
				Name:           run.result.Name,
				Jurisdiction:   run.request.Jurisdiction,
				CellStatus:     run.result.Status,
				ParticipantDID: participant.ParticipantDID,
				Role:           participant.Role,
				Reason:         participant.Reason,
				ExpiresAt:      participant.QuarantineExpiresAt.UTC(),
				UpdatedAt:      participant.UpdatedAt.UTC(),
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ExpiresAt.Equal(items[j].ExpiresAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].ParticipantDID < items[j].ParticipantDID
			}
			return items[i].CellID < items[j].CellID
		}
		return items[i].ExpiresAt.Before(items[j].ExpiresAt)
	})
	return items, nil
}

// ListOverdueDecisions returns operator-facing projections for governed
// decisions whose next automation milestone is overdue.
func (s *Service) ListOverdueDecisions(_ context.Context, filter SecureCellOverdueDecisionFilter) ([]SecureCellOverdueDecision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	statuses := make(map[SecureCellThreadDecisionStatus]struct{}, len(filter.Statuses))
	for _, status := range filter.Statuses {
		if status == "" {
			continue
		}
		statuses[status] = struct{}{}
	}

	cellID := strings.TrimSpace(filter.CellID)
	jurisdiction := strings.TrimSpace(filter.Jurisdiction)
	participantDID := strings.TrimSpace(filter.ParticipantDID)
	slaTemplate := strings.TrimSpace(strings.ToLower(filter.SLATemplate))
	sectorPolicyPack := strings.TrimSpace(strings.ToLower(filter.SectorPolicyPack))
	items := make([]SecureCellOverdueDecision, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		if jurisdiction != "" && !strings.EqualFold(strings.TrimSpace(run.request.Jurisdiction), jurisdiction) {
			continue
		}
		if participantDID != "" && !secureCellHasParticipant(run.result.Participants, participantDID) {
			continue
		}
		for _, decision := range run.result.Decisions {
			if slaTemplate != "" && !strings.EqualFold(strings.TrimSpace(decision.SLATemplate), slaTemplate) {
				continue
			}
			if sectorPolicyPack != "" && !strings.EqualFold(strings.TrimSpace(decision.SectorPolicyPack), sectorPolicyPack) {
				continue
			}
			if len(statuses) > 0 {
				if _, ok := statuses[decision.Status]; !ok {
					continue
				}
			}
			if participantDID != "" && !secureCellDecisionReferencesParticipant(decision, participantDID) {
				continue
			}
			action, reason, tierID, targetDID, dueAt, ok := secureCellDecisionOverdueAction(decision, at)
			if !ok {
				continue
			}
			items = append(items, SecureCellOverdueDecision{
				CellID:             run.result.CellID,
				Name:               run.result.Name,
				Jurisdiction:       run.request.Jurisdiction,
				CellStatus:         run.result.Status,
				SessionID:          decision.SessionID,
				ThreadID:           decision.ThreadID,
				DecisionID:         decision.ID,
				DecisionTitle:      decision.Title,
				DecisionStatus:     decision.Status,
				GovernanceTemplate: decision.GovernanceTemplate,
				SLATemplate:        decision.SLATemplate,
				SectorPolicyPack:   decision.SectorPolicyPack,
				AutomationAction:   action,
				OverdueReason:      reason,
				TierID:             tierID,
				TargetDID:          targetDID,
				DueAt:              dueAt.UTC(),
				OverdueSeconds:     int64(at.Sub(dueAt).Seconds()),
				EscalationDueAt:    cloneTimePtr(decision.EscalationDueAt),
				ResolutionDueAt:    cloneTimePtr(decision.ResolutionDueAt),
				UpdatedAt:          decision.UpdatedAt.UTC(),
			})
		}
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].DueAt.Equal(items[j].DueAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].DecisionID < items[j].DecisionID
			}
			return items[i].CellID < items[j].CellID
		}
		return items[i].DueAt.Before(items[j].DueAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

// ListDecisionAutomationActions returns automated decision actions already
// applied by SLA sweeps.
func (s *Service) ListDecisionAutomationActions(_ context.Context, filter SecureCellDecisionAutomationActionFilter) ([]SecureCellDecisionAutomationActionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cellID := strings.TrimSpace(filter.CellID)
	sessionID := strings.TrimSpace(filter.SessionID)
	threadID := strings.TrimSpace(filter.ThreadID)
	decisionID := strings.TrimSpace(filter.DecisionID)
	slaTemplate := strings.TrimSpace(strings.ToLower(filter.SLATemplate))
	sectorPolicyPack := strings.TrimSpace(strings.ToLower(filter.SectorPolicyPack))
	action := strings.TrimSpace(filter.Action)
	var since time.Time
	if filter.Since != nil && !filter.Since.IsZero() {
		since = filter.Since.UTC()
	}
	var until time.Time
	if filter.Until != nil && !filter.Until.IsZero() {
		until = filter.Until.UTC()
	}

	items := make([]SecureCellDecisionAutomationActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		for _, transition := range run.result.Transitions {
			if !secureCellTransitionAutomatedDecisionAction(transition) {
				continue
			}
			if sessionID != "" && !strings.EqualFold(strings.TrimSpace(transition.SessionID), sessionID) {
				continue
			}
			if threadID != "" && !strings.EqualFold(strings.TrimSpace(transition.ThreadID), threadID) {
				continue
			}
			if decisionID != "" && !strings.EqualFold(strings.TrimSpace(transition.DecisionID), decisionID) {
				continue
			}
			if action != "" && !strings.EqualFold(strings.TrimSpace(transition.Action), action) {
				continue
			}
			occurredAt := transition.OccurredAt.UTC()
			if !since.IsZero() && occurredAt.Before(since) {
				continue
			}
			if !until.IsZero() && occurredAt.After(until) {
				continue
			}
			decision, _ := secureCellDecisionLookup(run.result.Decisions, transition.DecisionID)
			if slaTemplate != "" {
				if decision == nil || !strings.EqualFold(strings.TrimSpace(decision.SLATemplate), slaTemplate) {
					continue
				}
			}
			if sectorPolicyPack != "" {
				if decision == nil || !strings.EqualFold(strings.TrimSpace(decision.SectorPolicyPack), sectorPolicyPack) {
					continue
				}
			}
			items = append(items, SecureCellDecisionAutomationActionRecord{
				CellID:               run.result.CellID,
				Name:                 run.result.Name,
				Jurisdiction:         run.request.Jurisdiction,
				CellStatus:           run.result.Status,
				SessionID:            transition.SessionID,
				ThreadID:             transition.ThreadID,
				DecisionID:           transition.DecisionID,
				DecisionTitle:        secureCellDecisionTitle(run.result.Decisions, transition.DecisionID),
				GovernanceTemplate:   safeString(decision, func(item *SecureCellThreadDecision) string { return item.GovernanceTemplate }),
				SLATemplate:          safeString(decision, func(item *SecureCellThreadDecision) string { return item.SLATemplate }),
				SectorPolicyPack:     safeString(decision, func(item *SecureCellThreadDecision) string { return item.SectorPolicyPack }),
				DecisionStatusBefore: transition.DecisionStatusBefore,
				DecisionStatusAfter:  transition.DecisionStatusAfter,
				Action:               transition.Action,
				TierID:               strings.TrimSpace(transition.Metadata["automation_tier_id"]),
				TargetDID:            firstNonEmpty(strings.TrimSpace(transition.Metadata["automation_target_did"]), strings.TrimSpace(transition.Metadata["decision_route_target"])),
				Trigger:              firstNonEmpty(strings.TrimSpace(transition.Metadata["decision_sweep_trigger"]), strings.TrimSpace(transition.Metadata["decision_sweep_action"])),
				DueAt:                parseSecureCellTransitionDueAt(transition.Metadata),
				Actor:                transition.Actor,
				AutomatedActor:       strings.TrimSpace(transition.Metadata["automated_actor"]),
				Reason:               transition.Reason,
				TransitionID:         transition.ID,
				OccurredAt:           occurredAt,
				Metadata:             cloneStringMap(transition.Metadata),
			})
		}
	}

	sort.SliceStable(items, func(i, j int) bool {
		if items[i].OccurredAt.Equal(items[j].OccurredAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].TransitionID > items[j].TransitionID
			}
			return items[i].CellID < items[j].CellID
		}
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
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
	actorDID := firstNonEmpty(strings.TrimSpace(mutation.ActorDID), run.request.OwnerIdentity.AgentID())
	receipt, err := s.evaluateStage(ctx, run.request, stage, lastReceiptHash(run.result), map[string]string{
		"target_participant_did":    targetDID,
		"target_role":               participant.Role,
		"cell_status_before":        string(run.result.Status),
		"participant_status_before": string(participant.Status),
		"participant_status_after":  string(targetStatus),
		"transition_reason":         strings.TrimSpace(mutation.Reason),
		"quarantine_expires_at":     strings.TrimSpace(safeTimeString(mutation.QuarantineExpiresAt)),
	}, actorDID)
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
		Actor:                   actorDID,
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
	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	receipt, err := s.evaluateStage(ctx, run.request, stage, lastReceiptHash(run.result), map[string]string{
		"cell_status_before": string(statusBefore),
		"cell_status_after":  string(statusAfter),
		"transition_reason":  strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
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
		Actor:            actorDID,
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

	sealReq := s.buildSealRequest(run.request, run.result.Participants, receiptChain, latestReceipt, stage)
	confidentialReq := s.buildConfidentialExecutionRequest(run.request, receiptChain, latestReceipt, sealReq, stage)
	confidentialPolicy := s.confidentialPolicyForRequest(run.request)
	if confidentialPolicy.Required {
		if s.config.ConfidentialAttestor == nil {
			return fmt.Errorf("securecells/service: confidential execution is required for cell %q but no attestor is configured", run.result.CellID)
		}
		teeAttestations, err := s.config.ConfidentialAttestor.Attest(ctx, confidentialReq)
		if err != nil {
			return fmt.Errorf("securecells/service: attest confidential execution: %w", err)
		}
		sealReq.TEEAttestations = teeAttestations
	}

	sealResp, err := s.config.Sealer.CreateSeal(ctx, sealReq)
	if err != nil {
		return fmt.Errorf("securecells/service: create seal: %w", err)
	}
	if len(sealResp.Attestations) > 0 || confidentialPolicy.Required {
		summary, err := confidential.VerifyAttestations(sealResp.Attestations, confidentialReq, confidentialPolicy)
		if err != nil {
			return fmt.Errorf("securecells/service: verify confidential execution: %w", err)
		}
		run.result.ConfidentialExecution = &summary
		run.result.ExecutionAttestations = confidential.BuildEvidenceAttestations(sealResp.Attestations, confidentialReq, summary, confidentialPolicy.TrustedValidatorKeys)
		if transition.Metadata == nil {
			transition.Metadata = make(map[string]string)
		}
		transition.Metadata["confidential_execution_verified"] = fmt.Sprintf("%t", summary.Verified)
		transition.Metadata["confidential_execution_valid_attestations"] = fmt.Sprintf("%d", summary.Valid)
		transition.Metadata["confidential_execution_binding_hash"] = summary.BindingHash
	} else {
		run.result.ConfidentialExecution = nil
		run.result.ExecutionAttestations = nil
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
	if err := s.persistRun(ctx, run); err != nil {
		return err
	}
	if s.config.EventPublisher != nil {
		s.config.EventPublisher(ctx, s.buildLifecycleEvent(run, transition))
	}
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

	actorDID := firstNonEmpty(strings.TrimSpace(admission.ActorDID), run.request.OwnerIdentity.AgentID())
	receipt, err := s.evaluateStage(ctx, run.request, "admit_member", lastReceiptHash(run.result), map[string]string{
		"target_participant_did":   admission.Participant.Identity.AgentID(),
		"target_role":              newState.Role,
		"cell_status_before":       string(run.result.Status),
		"participant_status_after": string(newState.Status),
		"transition_reason":        strings.TrimSpace(admission.Reason),
	}, actorDID)
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
		Actor:                   actorDID,
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
			ActorDID:       lifecycle.ActorDID,
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

// SweepExpiredQuarantines releases quarantined members whose expiry windows
// have elapsed across every secure cell currently managed by the service.
func (s *Service) SweepExpiredQuarantines(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellExpirySweepResult, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	items, err := s.ListExpiringQuarantines(ctx, at)
	if err != nil {
		return nil, err
	}
	report := &SecureCellExpirySweepResult{
		At:           at.UTC(),
		CellsScanned: s.runCount(),
	}
	if len(items) == 0 {
		return report, nil
	}

	uniqueCells := make(map[string]struct{}, len(items))
	releases := make([]SecureCellExpirySweepRelease, 0, len(items))
	for _, item := range items {
		uniqueCells[item.CellID] = struct{}{}
		releases = append(releases, SecureCellExpirySweepRelease{
			CellID:         item.CellID,
			ParticipantDID: item.ParticipantDID,
			ReleasedAt:     at.UTC(),
		})
	}
	cellIDs := make([]string, 0, len(uniqueCells))
	for cellID := range uniqueCells {
		cellIDs = append(cellIDs, cellID)
	}
	sort.Strings(cellIDs)

	for _, cellID := range cellIDs {
		if _, err := s.ExpireQuarantinedMembers(ctx, cellID, at, lifecycle); err != nil {
			return nil, err
		}
	}

	report.CellsMutated = len(cellIDs)
	report.ParticipantsReleased = len(releases)
	report.CellIDs = cellIDs
	report.Releases = releases
	return report, nil
}

// SweepDecisionGovernance applies automated escalation and deadline closure
// rules to governed decisions across every secure cell managed by the service.
func (s *Service) SweepDecisionGovernance(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellDecisionGovernanceSweepResult, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	s.mu.RLock()
	cellIDs := make([]string, 0, len(s.runs))
	for cellID := range s.runs {
		cellIDs = append(cellIDs, cellID)
	}
	s.mu.RUnlock()
	sort.Strings(cellIDs)

	report := &SecureCellDecisionGovernanceSweepResult{
		At:           at.UTC(),
		CellsScanned: len(cellIDs),
	}
	if len(cellIDs) == 0 {
		return report, nil
	}

	mutatedCells := make(map[string]struct{})
	for _, cellID := range cellIDs {
		run, err := s.getRun(cellID)
		if err != nil {
			return nil, err
		}
		report.DecisionsScanned += len(run.result.Decisions)

		type pendingAction struct {
			sessionID  string
			threadID   string
			decisionID string
			targetDID  string
			action     string
			tierID     string
			trigger    string
			dueAt      *time.Time
			reason     string
		}
		pending := make([]pendingAction, 0)
		for _, decision := range append([]SecureCellThreadDecision(nil), run.result.Decisions...) {
			if !decisionStatusAllowed(decision.Status, SecureCellThreadDecisionStatusOpen, SecureCellThreadDecisionStatusQuorumFailed) {
				continue
			}
			if decision.ResolutionDueAt != nil && !decision.ResolutionDueAt.After(at) {
				pending = append(pending, pendingAction{
					sessionID:  decision.SessionID,
					threadID:   decision.ThreadID,
					decisionID: decision.ID,
					action:     "close",
					trigger:    "resolution_due",
					dueAt:      cloneUTCTime(decision.ResolutionDueAt),
					reason:     "automated decision resolution deadline reached",
				})
				continue
			}
			if tier, ok := secureCellDecisionNextDueEscalationTier(decision, at); ok {
				pending = append(pending, pendingAction{
					sessionID:  decision.SessionID,
					threadID:   decision.ThreadID,
					decisionID: decision.ID,
					targetDID:  tier.TargetDID,
					action:     "escalate",
					tierID:     tier.TierID,
					trigger:    "escalation_tier_due",
					dueAt:      cloneUTCTime(tier.DueAt),
					reason:     firstNonEmpty(strings.TrimSpace(tier.Reason), "automated decision escalation deadline reached"),
				})
			}
		}

		for _, action := range pending {
			actorDID := run.request.OwnerIdentity.AgentID()
			baseMetadata := mergeStringMaps(lifecycle.Metadata, map[string]string{
				"decision_sweep_mode":    "automated",
				"decision_sweep_action":  action.action,
				"decision_sweep_trigger": action.trigger,
			})
			if automatedActor := strings.TrimSpace(lifecycle.ActorDID); automatedActor != "" && automatedActor != actorDID {
				baseMetadata["automated_actor"] = automatedActor
			}
			if action.tierID != "" {
				baseMetadata["automation_tier_id"] = action.tierID
			}
			if action.targetDID != "" {
				baseMetadata["automation_target_did"] = action.targetDID
			}
			if action.dueAt != nil {
				baseMetadata["decision_sweep_due_at"] = action.dueAt.UTC().Format(time.RFC3339Nano)
			}
			switch action.action {
			case "escalate":
				if _, err := s.EscalateThreadDecision(ctx, cellID, action.sessionID, action.threadID, action.decisionID, SecureCellThreadDecisionDelegationRequest{
					ActorDID:  actorDID,
					TargetDID: action.targetDID,
					Reason:    firstNonEmpty(strings.TrimSpace(lifecycle.Reason), action.reason),
					Metadata:  baseMetadata,
				}); err != nil {
					return nil, err
				}
				report.DecisionsEscalated++
			case "close":
				if _, err := s.CloseThreadDecision(ctx, cellID, action.sessionID, action.threadID, action.decisionID, SecureCellLifecycleRequest{
					ActorDID: actorDID,
					Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), action.reason),
					Metadata: baseMetadata,
				}); err != nil {
					return nil, err
				}
				report.DecisionsClosed++
			}
			mutatedCells[cellID] = struct{}{}
			report.Actions = append(report.Actions, SecureCellDecisionGovernanceSweepAction{
				CellID:     cellID,
				SessionID:  action.sessionID,
				ThreadID:   action.threadID,
				DecisionID: action.decisionID,
				Action:     action.action,
				TierID:     action.tierID,
				TargetDID:  action.targetDID,
				DueAt:      cloneUTCTime(action.dueAt),
				Trigger:    action.trigger,
				OccurredAt: at.UTC(),
			})
		}
	}

	if len(mutatedCells) > 0 {
		report.CellIDs = make([]string, 0, len(mutatedCells))
		for cellID := range mutatedCells {
			report.CellIDs = append(report.CellIDs, cellID)
		}
		sort.Strings(report.CellIDs)
		report.CellsMutated = len(report.CellIDs)
	}
	return report, nil
}

// BulkQuarantineMembers quarantines multiple participants under one operator
// request while preserving per-participant evidence chains.
func (s *Service) BulkQuarantineMembers(ctx context.Context, cellID string, bulk SecureCellBulkMemberTransitionRequest) (*SecureCellBulkMemberTransitionResult, error) {
	return s.bulkTransitionMembers(ctx, cellID, "secure_cell.member_quarantined", bulk, func(ctx context.Context, cellID string, mutation SecureCellMemberTransitionRequest) (*SecureCellResult, error) {
		return s.QuarantineMember(ctx, cellID, mutation)
	})
}

// BulkReleaseMembers releases multiple quarantined participants in sequence.
func (s *Service) BulkReleaseMembers(ctx context.Context, cellID string, bulk SecureCellBulkMemberTransitionRequest) (*SecureCellBulkMemberTransitionResult, error) {
	return s.bulkTransitionMembers(ctx, cellID, "secure_cell.member_released", bulk, func(ctx context.Context, cellID string, mutation SecureCellMemberTransitionRequest) (*SecureCellResult, error) {
		return s.ReleaseMember(ctx, cellID, mutation)
	})
}

// BulkRevokeMembers revokes multiple participants under one operator request.
func (s *Service) BulkRevokeMembers(ctx context.Context, cellID string, bulk SecureCellBulkMemberTransitionRequest) (*SecureCellBulkMemberTransitionResult, error) {
	return s.bulkTransitionMembers(ctx, cellID, "secure_cell.member_revoked", bulk, func(ctx context.Context, cellID string, mutation SecureCellMemberTransitionRequest) (*SecureCellResult, error) {
		return s.RevokeMember(ctx, cellID, mutation)
	})
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
	ledger.WithMetadata("federation_organizations_total", fmt.Sprintf("%d", len(run.result.FederationOrganizations)))
	ledger.WithMetadata("federation_invitations_total", fmt.Sprintf("%d", len(run.result.FederationInvitations)))
	ledger.WithMetadata("federation_counterproposals_total", fmt.Sprintf("%d", len(run.result.FederationCounterproposals)))
	ledger.WithMetadata("federation_counterproposals_pending", fmt.Sprintf("%d", len(secureCellFederationCounterproposalsByStatus(run.result.FederationCounterproposals, SecureCellFederationCounterproposalStatusPending))))
	ledger.WithMetadata("federation_counterproposals_approved", fmt.Sprintf("%d", len(secureCellFederationCounterproposalsByStatus(run.result.FederationCounterproposals, SecureCellFederationCounterproposalStatusApproved))))
	ledger.WithMetadata("federation_counterproposals_rejected", fmt.Sprintf("%d", len(secureCellFederationCounterproposalsByStatus(run.result.FederationCounterproposals, SecureCellFederationCounterproposalStatusRejected))))
	ledger.WithMetadata("federation_counterproposals_superseded", fmt.Sprintf("%d", len(secureCellFederationCounterproposalsByStatus(run.result.FederationCounterproposals, SecureCellFederationCounterproposalStatusSuperseded))))
	ledger.WithMetadata("federation_contracts_total", fmt.Sprintf("%d", len(run.result.FederationContracts)))
	ledger.WithMetadata("federation_contracts_active", fmt.Sprintf("%d", len(secureCellFederationContractsByStatus(run.result.FederationContracts, SecureCellFederationContractStatusActive))))
	ledger.WithMetadata("federation_contracts_suspended", fmt.Sprintf("%d", len(secureCellFederationContractsByStatus(run.result.FederationContracts, SecureCellFederationContractStatusSuspended))))
	ledger.WithMetadata("federation_contracts_revoked", fmt.Sprintf("%d", len(secureCellFederationContractsByStatus(run.result.FederationContracts, SecureCellFederationContractStatusRevoked))))
	ledger.WithMetadata("federation_counterparty_assurance_total", fmt.Sprintf("%d", len(run.result.FederationCounterpartyAssurance)))
	ledger.WithMetadata("federation_counterparty_assurance_verified", fmt.Sprintf("%d", len(secureCellFederationCounterpartyAssuranceByStatus(run.result.FederationCounterpartyAssurance, SecureCellFederationCounterpartyAssuranceStatusVerified))))
	ledger.WithMetadata("federation_counterparty_assurance_stale", fmt.Sprintf("%d", len(secureCellFederationCounterpartyAssuranceByStatus(run.result.FederationCounterpartyAssurance, SecureCellFederationCounterpartyAssuranceStatusStale))))
	ledger.WithMetadata("federation_counterparty_assurance_expired", fmt.Sprintf("%d", len(secureCellFederationCounterpartyAssuranceByStatus(run.result.FederationCounterpartyAssurance, SecureCellFederationCounterpartyAssuranceStatusExpired))))
	ledger.WithMetadata("federation_counterparty_assurance_invalid", fmt.Sprintf("%d", len(secureCellFederationCounterpartyAssuranceByStatus(run.result.FederationCounterpartyAssurance, SecureCellFederationCounterpartyAssuranceStatusInvalid))))
	ledger.WithMetadata("federation_incidents_total", fmt.Sprintf("%d", len(run.result.FederationIncidents)))
	ledger.WithMetadata("federation_incidents_open", fmt.Sprintf("%d", len(secureCellFederationIncidentsByStatus(run.result.FederationIncidents, SecureCellFederationIncidentStatusOpen))))
	ledger.WithMetadata("federation_incidents_resolved", fmt.Sprintf("%d", len(secureCellFederationIncidentsByStatus(run.result.FederationIncidents, SecureCellFederationIncidentStatusResolved))))
	ledger.WithMetadata("federation_incidents_critical", fmt.Sprintf("%d", secureCellFederationIncidentSeverityCount(run.result.FederationIncidents, SecureCellFederationIncidentSeverityCritical)))
	ledger.WithMetadata("federation_incidents_high", fmt.Sprintf("%d", secureCellFederationIncidentSeverityCount(run.result.FederationIncidents, SecureCellFederationIncidentSeverityHigh)))
	ledger.WithMetadata("federation_counterparty_incidents_total", fmt.Sprintf("%d", len(run.result.FederationCounterpartyIncidents)))
	ledger.WithMetadata("federation_counterparty_incidents_verified", fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentsByStatus(run.result.FederationCounterpartyIncidents, SecureCellFederationCounterpartyIncidentStatusVerified))))
	ledger.WithMetadata("federation_counterparty_incidents_stale", fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentsByStatus(run.result.FederationCounterpartyIncidents, SecureCellFederationCounterpartyIncidentStatusStale))))
	ledger.WithMetadata("federation_counterparty_incidents_expired", fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentsByStatus(run.result.FederationCounterpartyIncidents, SecureCellFederationCounterpartyIncidentStatusExpired))))
	ledger.WithMetadata("federation_counterparty_incidents_invalid", fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentsByStatus(run.result.FederationCounterpartyIncidents, SecureCellFederationCounterpartyIncidentStatusInvalid))))
	ledger.WithMetadata("federation_counterparty_incident_reports_total", fmt.Sprintf("%d", len(run.result.FederationCounterpartyIncidentReports)))
	ledger.WithMetadata("federation_counterparty_incident_reports_verified", fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentReportsByStatus(run.result.FederationCounterpartyIncidentReports, SecureCellFederationCounterpartyIncidentReportStatusVerified))))
	ledger.WithMetadata("federation_counterparty_incident_reports_stale", fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentReportsByStatus(run.result.FederationCounterpartyIncidentReports, SecureCellFederationCounterpartyIncidentReportStatusStale))))
	ledger.WithMetadata("federation_counterparty_incident_reports_expired", fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentReportsByStatus(run.result.FederationCounterpartyIncidentReports, SecureCellFederationCounterpartyIncidentReportStatusExpired))))
	ledger.WithMetadata("federation_counterparty_incident_reports_invalid", fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentReportsByStatus(run.result.FederationCounterpartyIncidentReports, SecureCellFederationCounterpartyIncidentReportStatusInvalid))))
	ledger.WithMetadata("federation_incident_responses_total", fmt.Sprintf("%d", len(run.result.FederationIncidentResponses)))
	ledger.WithMetadata("federation_incident_responses_pending_local_ack", fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusPendingLocalAck))))
	ledger.WithMetadata("federation_incident_responses_pending_counterparty_ack", fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusPendingCounterpartyAck))))
	ledger.WithMetadata("federation_incident_responses_acknowledged", fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusAcknowledged))))
	ledger.WithMetadata("federation_incident_responses_escalated", fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusEscalated))))
	ledger.WithMetadata("federation_incident_responses_remediating", fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusRemediating))))
	ledger.WithMetadata("federation_incident_responses_remediated", fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusRemediated))))
	ledger.WithMetadata("federation_incident_responses_closed", fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusClosed))))
	ledger.WithMetadata("federation_incident_reports_total", fmt.Sprintf("%d", secureCellFederationIncidentResponseReportTotal(run.result.FederationIncidentResponses)))
	ledger.WithMetadata("federation_incident_remediations_total", fmt.Sprintf("%d", secureCellFederationIncidentResponseRemediationTotal(run.result.FederationIncidentResponses)))
	ledger.WithMetadata("federation_incident_verifications_total", fmt.Sprintf("%d", secureCellFederationIncidentResponseVerificationTotal(run.result.FederationIncidentResponses)))
	ledger.WithMetadata("federation_incident_directive_extensions_total", fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionTotal(run.result.FederationIncidentResponses)))
	ledger.WithMetadata("federation_incident_directive_extension_disputes_total", fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionDisputeCount(run.result.FederationIncidentResponses)))
	ledger.WithMetadata("federation_incident_directive_extension_appeals_total", fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealCount(run.result.FederationIncidentResponses)))
	ledger.WithMetadata("federation_incident_directive_extension_pending_appeals_total", fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionPendingAppealCount(run.result.FederationIncidentResponses)))
	ledger.WithMetadata("federation_incident_directive_extension_appeal_reconciliation_challenge_appeals_total", fmt.Sprintf("%d", len(secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealsFromRun(run))))
	ledger.WithMetadata("federation_counterparty_incident_directive_extension_appeals_total", fmt.Sprintf("%d", len(run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals)))
	ledger.WithMetadata("federation_counterparty_incident_directive_extension_appeals_verified", fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentDirectiveExtensionAppealsByStatus(run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals, SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusVerified))))
	ledger.WithMetadata("federation_counterparty_incident_directive_extension_appeals_stale", fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentDirectiveExtensionAppealsByStatus(run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals, SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusStale))))
	ledger.WithMetadata("federation_counterparty_incident_directive_extension_appeals_expired", fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentDirectiveExtensionAppealsByStatus(run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals, SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusExpired))))
	ledger.WithMetadata("federation_counterparty_incident_directive_extension_appeals_invalid", fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentDirectiveExtensionAppealsByStatus(run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals, SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusInvalid))))
	ledger.WithMetadata("sessions_total", fmt.Sprintf("%d", len(run.result.Sessions)))
	ledger.WithMetadata("sessions_active", fmt.Sprintf("%d", len(sessionsByStatus(run.result.Sessions, SecureCellSessionStatusActive))))
	ledger.WithMetadata("threads_total", fmt.Sprintf("%d", len(run.result.Threads)))
	ledger.WithMetadata("threads_active", fmt.Sprintf("%d", len(threadsByStatus(run.result.Threads, SecureCellThreadStatusActive))))
	ledger.WithMetadata("threads_quarantined", fmt.Sprintf("%d", len(threadsByStatus(run.result.Threads, SecureCellThreadStatusQuarantined))))
	ledger.WithMetadata("threads_closed", fmt.Sprintf("%d", len(threadsByStatus(run.result.Threads, SecureCellThreadStatusClosed))))
	ledger.WithMetadata("decisions_total", fmt.Sprintf("%d", len(run.result.Decisions)))
	ledger.WithMetadata("decisions_open", fmt.Sprintf("%d", len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusOpen))))
	ledger.WithMetadata("decisions_approved", fmt.Sprintf("%d", len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusApproved))))
	ledger.WithMetadata("decisions_quorum_failed", fmt.Sprintf("%d", len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusQuorumFailed))))
	ledger.WithMetadata("decisions_quarantined", fmt.Sprintf("%d", len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusQuarantined))))
	ledger.WithMetadata("decisions_closed", fmt.Sprintf("%d", len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusClosed))))
	ledger.WithMetadata("decision_approval_votes_total", fmt.Sprintf("%d", secureCellDecisionVoteTotal(run.result.Decisions)))
	ledger.WithMetadata("decision_comments_total", fmt.Sprintf("%d", secureCellDecisionCommentTotal(run.result.Decisions)))
	ledger.WithMetadata("decision_delegations_total", fmt.Sprintf("%d", secureCellDecisionDelegationTotal(run.result.Decisions)))
	ledger.WithMetadata("decision_outcomes_total", fmt.Sprintf("%d", len(run.result.DecisionOutcomes)))
	ledger.WithMetadata("shared_outputs_total", fmt.Sprintf("%d", len(run.result.SharedOutputs)))
	ledger.WithMetadata("session_exchanges_total", fmt.Sprintf("%d", len(run.result.SessionExchanges)))
	ledger.WithMetadata("contained_shared_outputs_total", fmt.Sprintf("%d", secureCellContainedSharedOutputTotal(run.result.SharedOutputs)))
	ledger.WithMetadata("contained_session_exchanges_total", fmt.Sprintf("%d", secureCellContainedSessionExchangeTotal(run.result.SessionExchanges)))
	if run.result.ConfidentialExecution != nil {
		ledger.WithMetadata("confidential_execution_verified", fmt.Sprintf("%t", run.result.ConfidentialExecution.Verified))
		ledger.WithMetadata("confidential_execution_present", fmt.Sprintf("%d", run.result.ConfidentialExecution.Present))
		ledger.WithMetadata("confidential_execution_valid", fmt.Sprintf("%d", run.result.ConfidentialExecution.Valid))
		ledger.WithMetadata("confidential_execution_binding_hash", run.result.ConfidentialExecution.BindingHash)
		ledger.WithMetadata("confidential_execution_output_hash", run.result.ConfidentialExecution.BoundOutputHash)
	}
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
	sessionLifecycleRecordIDs := make([]string, 0, len(run.result.Transitions))
	threadLifecycleRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationLifecycleRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationCounterproposalRecordIDs := make([]string, 0, len(run.result.FederationCounterproposals))
	federationContractRecordIDs := make([]string, 0, len(run.result.FederationContracts))
	federationContractPolicyReceiptIDs := make([]string, 0, len(run.result.FederationContracts))
	federationCounterpartyAssuranceRecordIDs := make([]string, 0, len(run.result.FederationCounterpartyAssurance))
	federationIncidentRecordIDs := make([]string, 0, len(run.result.FederationIncidents))
	federationCounterpartyIncidentRecordIDs := make([]string, 0, len(run.result.FederationCounterpartyIncidents))
	federationCounterpartyIncidentReportRecordIDs := make([]string, 0, len(run.result.FederationCounterpartyIncidentReports))
	federationCounterpartyIncidentReportAmendmentRecordIDs := make([]string, 0, len(run.result.FederationCounterpartyIncidentReportAmendments))
	federationCounterpartyIncidentDirectiveExtensionAppealRecordIDs := make([]string, 0, len(run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals))
	federationIncidentActionRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentResponseRecordIDs := make([]string, 0, len(run.result.FederationIncidentResponses))
	federationIncidentResponseActionRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentDirectiveRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentDirectiveExtensionRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentDirectiveExtensionDisputeRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentDirectiveExtensionAppealRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentDirectiveExtensionAppealAutomationRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentDirectiveExtensionAppealReconciliationRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentDirectiveExtensionAppealReconciliationChallengeRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentDirectiveExtensionAppealReconciliationAttestationRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentDirectiveExtensionAppealReconciliationAutomationRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentDirectiveExtensionAutomationRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentRemediationRecordIDs := make([]string, 0, secureCellFederationIncidentResponseRemediationTotal(run.result.FederationIncidentResponses))
	federationIncidentVerificationRecordIDs := make([]string, 0, secureCellFederationIncidentResponseVerificationTotal(run.result.FederationIncidentResponses))
	federationIncidentReportRecordIDs := make([]string, 0, secureCellFederationIncidentResponseReportTotal(run.result.FederationIncidentResponses))
	federationIncidentReportAmendmentRecordIDs := make([]string, 0, secureCellFederationIncidentResponseReportAmendmentTotal(run.result.FederationIncidentResponses))
	federationIncidentReportReconciliationRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentReportAmendmentReconciliationRecordIDs := make([]string, 0, len(run.result.Transitions))
	federationIncidentReportAmendmentReconciliationAttestationRecordIDs := make([]string, 0, len(run.result.Transitions))
	sessionEvidenceRecordIDs := make([]string, 0, len(run.result.Sessions))
	threadEvidenceRecordIDs := make([]string, 0, len(run.result.Threads))
	decisionLifecycleRecordIDs := make([]string, 0, len(run.result.Transitions))
	decisionEvidenceRecordIDs := make([]string, 0, len(run.result.Decisions))
	decisionVoteRecordIDs := make([]string, 0, len(run.result.Decisions))
	decisionCommentRecordIDs := make([]string, 0, len(run.result.Decisions))
	decisionDelegationRecordIDs := make([]string, 0, len(run.result.Decisions))
	decisionOutcomeRecordIDs := make([]string, 0, len(run.result.DecisionOutcomes))
	decisionArtifactContainmentRecordIDs := make([]string, 0, len(run.result.Transitions))
	sessionExchangeRecordIDs := make([]string, 0, len(run.result.SessionExchanges))
	sessionExchangePolicyReceiptIDs := make([]string, 0, len(run.result.SessionExchanges))
	sessionExchangeSealIDs := make([]string, 0, len(run.result.SessionExchanges))
	sessionExchangeTraceLinkIDs := make([]string, 0, len(run.result.SessionExchanges))
	threadMessageRecordIDs := make([]string, 0, len(run.result.SessionExchanges))
	threadMessagePolicyReceiptIDs := make([]string, 0, len(run.result.SessionExchanges))
	threadMessageSealIDs := make([]string, 0, len(run.result.SessionExchanges))
	threadMessageTraceLinkIDs := make([]string, 0, len(run.result.SessionExchanges))
	sharedOutputRecordIDs := make([]string, 0, len(run.result.SharedOutputs))
	sharedOutputPolicyReceiptIDs := make([]string, 0, len(run.result.SharedOutputs))
	sharedOutputSealIDs := make([]string, 0, len(run.result.SharedOutputs))
	sharedOutputTraceLinkIDs := make([]string, 0, len(run.result.SharedOutputs))
	executionAttestationIDs := make([]string, 0, len(run.result.ExecutionAttestations))
	admittedParticipants := make(map[string]struct{}, len(run.result.Transitions))
	sharedOutputTransitions := make(map[string]SecureCellTransition, len(run.result.SharedOutputs))

	for _, participant := range req.Participants {
		passport, err := evidence.NewAgentPassportEvidence(participant.Identity)
		if err != nil {
			return nil, fmt.Errorf("securecells/service: create participant passport evidence: %w", err)
		}
		ledger.AddAgentPassport(passport)
	}
	for _, attestation := range run.result.ExecutionAttestations {
		ledger.AddAttestation(attestation)
		executionAttestationIDs = append(executionAttestationIDs, attestation.ID)
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
		if transition.ThreadID != "" {
			data["thread_id"] = transition.ThreadID
		}
		if transition.ThreadStatusBefore != "" {
			data["thread_status_before"] = string(transition.ThreadStatusBefore)
		}
		if transition.ThreadStatusAfter != "" {
			data["thread_status_after"] = string(transition.ThreadStatusAfter)
		}
		if transition.DecisionID != "" {
			data["decision_id"] = transition.DecisionID
		}
		if transition.DecisionStatusBefore != "" {
			data["decision_status_before"] = string(transition.DecisionStatusBefore)
		}
		if transition.DecisionStatusAfter != "" {
			data["decision_status_after"] = string(transition.DecisionStatusAfter)
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
		if transition.Action == "secure_cell.federation_joined" {
			if participantDID := strings.TrimSpace(data["target_participant_did"]); participantDID != "" {
				admittedParticipants[participantDID] = struct{}{}
			}
			federationLifecycleRecordIDs = append(federationLifecycleRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_invited" || transition.Action == "secure_cell.federation_invitation_revoked" || transition.Action == "secure_cell.federation_counterproposed" || transition.Action == "secure_cell.federation_counterproposal_vote_recorded" || transition.Action == "secure_cell.federation_counterproposal_escalated" || transition.Action == "secure_cell.federation_counterproposal_approved" || transition.Action == "secure_cell.federation_counterproposal_rejected" || transition.Action == "secure_cell.federation_contract_revoked" || transition.Action == "secure_cell.federation_contract_renewed" || transition.Action == "secure_cell.federation_contract_suspended" || transition.Action == "secure_cell.federation_contract_resumed" || transition.Action == "secure_cell.federation_assurance_ingested" || transition.Action == "secure_cell.federation_incident_published" || transition.Action == "secure_cell.federation_incident_resolved" || transition.Action == "secure_cell.federation_incident_bulletin_ingested" || transition.Action == "secure_cell.federation_incident_report_bundle_ingested" || transition.Action == "secure_cell.federation_incident_report_amendment_bundle_ingested" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_bundle_ingested" || transition.Action == "secure_cell.federation_incident_response_acknowledged" || transition.Action == "secure_cell.federation_incident_response_escalated" || transition.Action == "secure_cell.federation_incident_response_remediation_attested" || transition.Action == "secure_cell.federation_incident_remediation_verified" || transition.Action == "secure_cell.federation_incident_closure_attested" || transition.Action == "secure_cell.federation_incident_response_disputed" || transition.Action == "secure_cell.federation_incident_directive_issued" || transition.Action == "secure_cell.federation_incident_directive_acknowledged" || transition.Action == "secure_cell.federation_incident_directive_completed" || transition.Action == "secure_cell.federation_incident_directive_verified" || transition.Action == "secure_cell.federation_incident_directive_extension_requested" || transition.Action == "secure_cell.federation_incident_directive_extension_approved" || transition.Action == "secure_cell.federation_incident_directive_extension_rejected" || transition.Action == "secure_cell.federation_incident_directive_extension_disputed" || transition.Action == "secure_cell.federation_incident_directive_extension_dispute_resolved" || transition.Action == "secure_cell.federation_incident_directive_extension_dispute_appealed" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_vote_recorded" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_ruled" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_review_delegated" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_review_recused" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_rehearing_requested" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_enforcement_acknowledged" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_acknowledged" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_disputed" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_resolved" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_dispute_acknowledged" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_correction_attested" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_resolution_attested" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appealed" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_vote_recorded" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruled" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_acknowledged" || transition.Action == "secure_cell.federation_incident_report_planned" || transition.Action == "secure_cell.federation_incident_report_amendment_created" || transition.Action == "secure_cell.federation_incident_report_submitted" || transition.Action == "secure_cell.federation_incident_report_acknowledged" || transition.Action == "secure_cell.federation_incident_report_amendment_submitted" || transition.Action == "secure_cell.federation_incident_report_amendment_acknowledged" || transition.Action == "secure_cell.federation_incident_report_reconciliation_acknowledged" || transition.Action == "secure_cell.federation_incident_report_reconciliation_disputed" || transition.Action == "secure_cell.federation_incident_report_reconciliation_resolved" || transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_acknowledged" || transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_disputed" || transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_resolved" || transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_dispute_acknowledged" || transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_correction_attested" || transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_resolution_attested" || transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_escalated" {
			federationLifecycleRecordIDs = append(federationLifecycleRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_assurance_ingested" {
			federationCounterpartyAssuranceRecordIDs = append(federationCounterpartyAssuranceRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_published" || transition.Action == "secure_cell.federation_incident_resolved" {
			federationIncidentRecordIDs = append(federationIncidentRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_bulletin_ingested" {
			federationCounterpartyIncidentRecordIDs = append(federationCounterpartyIncidentRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_report_bundle_ingested" {
			federationCounterpartyIncidentReportRecordIDs = append(federationCounterpartyIncidentReportRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_report_amendment_bundle_ingested" {
			federationCounterpartyIncidentReportAmendmentRecordIDs = append(federationCounterpartyIncidentReportAmendmentRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_directive_extension_appeal_bundle_ingested" {
			federationCounterpartyIncidentDirectiveExtensionAppealRecordIDs = append(federationCounterpartyIncidentDirectiveExtensionAppealRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_directive_issued" || transition.Action == "secure_cell.federation_incident_directive_acknowledged" || transition.Action == "secure_cell.federation_incident_directive_completed" || transition.Action == "secure_cell.federation_incident_directive_verified" || transition.Action == "secure_cell.federation_incident_directive_extension_requested" || transition.Action == "secure_cell.federation_incident_directive_extension_approved" || transition.Action == "secure_cell.federation_incident_directive_extension_rejected" || transition.Action == "secure_cell.federation_incident_directive_extension_disputed" || transition.Action == "secure_cell.federation_incident_directive_extension_dispute_resolved" || transition.Action == "secure_cell.federation_incident_directive_extension_dispute_appealed" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_vote_recorded" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_ruled" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_review_delegated" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_review_recused" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_rehearing_requested" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_enforcement_acknowledged" {
			federationIncidentDirectiveRecordIDs = append(federationIncidentDirectiveRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_directive_extension_requested" || transition.Action == "secure_cell.federation_incident_directive_extension_approved" || transition.Action == "secure_cell.federation_incident_directive_extension_rejected" || transition.Action == "secure_cell.federation_incident_directive_extension_disputed" || transition.Action == "secure_cell.federation_incident_directive_extension_dispute_resolved" || transition.Action == "secure_cell.federation_incident_directive_extension_dispute_appealed" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_vote_recorded" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_ruled" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_review_delegated" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_review_recused" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_rehearing_requested" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_enforcement_acknowledged" {
			federationIncidentDirectiveExtensionRecordIDs = append(federationIncidentDirectiveExtensionRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_directive_extension_disputed" || transition.Action == "secure_cell.federation_incident_directive_extension_dispute_resolved" {
			federationIncidentDirectiveExtensionDisputeRecordIDs = append(federationIncidentDirectiveExtensionDisputeRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_directive_extension_dispute_appealed" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_vote_recorded" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_ruled" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_review_delegated" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_review_recused" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_rehearing_requested" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_enforcement_acknowledged" {
			federationIncidentDirectiveExtensionAppealRecordIDs = append(federationIncidentDirectiveExtensionAppealRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_directive_extension_review_vote_recorded" || transition.Action == "secure_cell.federation_incident_directive_extension_review_delegated" || transition.Action == "secure_cell.federation_incident_directive_extension_dispute_resolution_vote_recorded" || transition.Action == "secure_cell.federation_incident_directive_extension_dispute_resolution_delegated" {
			federationLifecycleRecordIDs = append(federationLifecycleRecordIDs, recordID)
			federationIncidentDirectiveRecordIDs = append(federationIncidentDirectiveRecordIDs, recordID)
			federationIncidentDirectiveExtensionRecordIDs = append(federationIncidentDirectiveExtensionRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_directive_extension_appeal_vote_recorded" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_review_delegated" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_review_recused" {
			federationLifecycleRecordIDs = append(federationLifecycleRecordIDs, recordID)
			federationIncidentDirectiveRecordIDs = append(federationIncidentDirectiveRecordIDs, recordID)
			federationIncidentDirectiveExtensionRecordIDs = append(federationIncidentDirectiveExtensionRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_directive_extension_dispute_resolution_vote_recorded" || transition.Action == "secure_cell.federation_incident_directive_extension_dispute_resolution_delegated" {
			federationIncidentDirectiveExtensionDisputeRecordIDs = append(federationIncidentDirectiveExtensionDisputeRecordIDs, recordID)
		}
		if strings.TrimSpace(data["federation_incident_directive_extension_id"]) != "" && strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_sweep_mode"]), "automated") {
			federationIncidentDirectiveExtensionAutomationRecordIDs = append(federationIncidentDirectiveExtensionAutomationRecordIDs, recordID)
		}
		if strings.TrimSpace(data["federation_incident_directive_extension_appeal_id"]) != "" && strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_appeal_sweep_mode"]), "automated") {
			federationIncidentDirectiveExtensionAppealAutomationRecordIDs = append(federationIncidentDirectiveExtensionAppealAutomationRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_report_amendment_created" || transition.Action == "secure_cell.federation_incident_report_amendment_submitted" || transition.Action == "secure_cell.federation_incident_report_amendment_acknowledged" {
			federationIncidentReportAmendmentRecordIDs = append(federationIncidentReportAmendmentRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_report_reconciliation_acknowledged" || transition.Action == "secure_cell.federation_incident_report_reconciliation_disputed" || transition.Action == "secure_cell.federation_incident_report_reconciliation_resolved" {
			federationIncidentReportReconciliationRecordIDs = append(federationIncidentReportReconciliationRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_acknowledged" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_disputed" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_resolved" {
			federationIncidentDirectiveExtensionAppealReconciliationRecordIDs = append(federationIncidentDirectiveExtensionAppealReconciliationRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenged" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_review_delegated" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_vote_recorded" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_ruled" {
			federationLifecycleRecordIDs = append(federationLifecycleRecordIDs, recordID)
			federationIncidentDirectiveRecordIDs = append(federationIncidentDirectiveRecordIDs, recordID)
			federationIncidentDirectiveExtensionRecordIDs = append(federationIncidentDirectiveExtensionRecordIDs, recordID)
			federationIncidentDirectiveExtensionAppealReconciliationChallengeRecordIDs = append(federationIncidentDirectiveExtensionAppealReconciliationChallengeRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appealed" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_vote_recorded" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruled" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_acknowledged" {
			federationLifecycleRecordIDs = append(federationLifecycleRecordIDs, recordID)
			federationIncidentDirectiveRecordIDs = append(federationIncidentDirectiveRecordIDs, recordID)
			federationIncidentDirectiveExtensionRecordIDs = append(federationIncidentDirectiveExtensionRecordIDs, recordID)
			federationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecordIDs = append(federationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_dispute_acknowledged" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_correction_attested" || transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_resolution_attested" {
			federationIncidentDirectiveExtensionAppealReconciliationAttestationRecordIDs = append(federationIncidentDirectiveExtensionAppealReconciliationAttestationRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_directive_extension_appeal_reconciliation_escalated" {
			federationIncidentDirectiveExtensionAppealReconciliationAutomationRecordIDs = append(federationIncidentDirectiveExtensionAppealReconciliationAutomationRecordIDs, recordID)
		}
		if strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]) != "" && strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_sweep_mode"]), "automated") {
			federationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationRecordIDs = append(federationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_acknowledged" || transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_disputed" || transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_resolved" {
			federationIncidentReportAmendmentReconciliationRecordIDs = append(federationIncidentReportAmendmentReconciliationRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_dispute_acknowledged" || transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_correction_attested" || transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_resolution_attested" || transition.Action == "secure_cell.federation_incident_report_amendment_reconciliation_escalated" {
			federationIncidentReportAmendmentReconciliationAttestationRecordIDs = append(federationIncidentReportAmendmentReconciliationAttestationRecordIDs, recordID)
		}
		if strings.TrimSpace(data["federation_incident_id"]) != "" {
			federationIncidentActionRecordIDs = append(federationIncidentActionRecordIDs, recordID)
		}
		if strings.TrimSpace(data["federation_incident_response_id"]) != "" {
			federationIncidentResponseActionRecordIDs = append(federationIncidentResponseActionRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.member_quarantined" || transition.Action == "secure_cell.member_revoked" || transition.Action == "secure_cell.member_released" || transition.Action == "secure_cell.quarantine_expired" {
			containmentRecordIDs = append(containmentRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.session_started" || transition.Action == "secure_cell.session_closed" || transition.Action == "secure_cell.session_paused" || transition.Action == "secure_cell.session_resumed" || transition.Action == "secure_cell.session_quarantined" || transition.Action == "secure_cell.session_member_admitted" || transition.Action == "secure_cell.session_member_removed" {
			sessionLifecycleRecordIDs = append(sessionLifecycleRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.session_thread_started" || transition.Action == "secure_cell.session_thread_closed" || transition.Action == "secure_cell.session_thread_resumed" || transition.Action == "secure_cell.session_thread_quarantined" {
			threadLifecycleRecordIDs = append(threadLifecycleRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.session_thread_decision_created" || transition.Action == "secure_cell.session_thread_decision_voted" || transition.Action == "secure_cell.session_thread_decision_approved" || transition.Action == "secure_cell.session_thread_decision_commented" || transition.Action == "secure_cell.session_thread_decision_delegated" || transition.Action == "secure_cell.session_thread_decision_escalated" || transition.Action == "secure_cell.session_thread_decision_outcome_published" || transition.Action == "secure_cell.session_thread_decision_resumed" || transition.Action == "secure_cell.session_thread_decision_closed" || transition.Action == "secure_cell.session_thread_decision_quarantined" || transition.Action == "secure_cell.session_thread_decision_outputs_contained" || transition.Action == "secure_cell.session_thread_decision_outputs_released" {
			decisionLifecycleRecordIDs = append(decisionLifecycleRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.session_shared" && transition.SharedOutputID != "" {
			sharedOutputTransitions[transition.SharedOutputID] = transition
		}
		if transition.Action == "secure_cell.session_exchange" && transition.SessionExchangeID != "" {
			sharedOutputTransitions[transition.SessionExchangeID] = transition
		}
		if transition.Action == "secure_cell.session_quarantined" {
			containmentRecordIDs = append(containmentRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.session_thread_quarantined" {
			containmentRecordIDs = append(containmentRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.session_thread_decision_quarantined" {
			containmentRecordIDs = append(containmentRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.session_thread_decision_outputs_contained" || transition.Action == "secure_cell.session_thread_decision_outputs_released" {
			containmentRecordIDs = append(containmentRecordIDs, recordID)
			decisionArtifactContainmentRecordIDs = append(decisionArtifactContainmentRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.federation_incident_artifacts_contained" {
			containmentRecordIDs = append(containmentRecordIDs, recordID)
		}
	}

	for _, contract := range run.result.FederationContracts {
		recordID := fmt.Sprintf("%s-federation-contract-%x", cellID(req), sha256.Sum256([]byte(contract.ID)))
		federationContractRecordIDs = append(federationContractRecordIDs, recordID)
		data := map[string]string{
			"federation_contract_id":     contract.ID,
			"federation_organization_id": contract.OrganizationID,
			"federation_invitation_id":   contract.InvitationID,
			"sponsor_of_record":          contract.SponsorOfRecord,
			"organization_name":          contract.OrganizationName,
			"jurisdiction":               contract.Jurisdiction,
			"status":                     string(contract.Status),
			"participant_dids":           strings.Join(contract.ParticipantDIDs, ","),
			"session_scope_ids":          strings.Join(contract.SessionScopeIDs, ","),
			"data_classes":               strings.Join(contract.DataClasses, ","),
			"compute_zones":              strings.Join(contract.ComputeZones, ","),
			"allowed_actions":            strings.Join(contract.AllowedActions, ","),
			"offered_session_scope_ids":  strings.Join(contract.OfferedSessionScopeIDs, ","),
			"offered_data_classes":       strings.Join(contract.OfferedDataClasses, ","),
			"offered_compute_zones":      strings.Join(contract.OfferedComputeZones, ","),
			"offered_actions":            strings.Join(contract.OfferedActions, ","),
			"negotiation_diffs":          secureCellFederationPolicyDiffsSummary(contract.NegotiationDiffs),
			"resource":                   contract.Resource,
			"negotiation_id":             contract.NegotiationID,
			"credential_id":              contract.CredentialID,
			"policy_receipt_id":          contract.PolicyReceiptID,
			"policy_receipt_hash":        contract.PolicyReceiptHash,
			"revision":                   fmt.Sprintf("%d", contract.Revision),
			"supersedes_contract_id":     contract.SupersedesContractID,
			"replaced_by_contract_id":    contract.ReplacedByContractID,
			"created_by":                 contract.CreatedBy,
			"activated_by":               contract.ActivatedBy,
			"suspended_by":               contract.SuspendedBy,
			"resumed_by":                 contract.ResumedBy,
			"revoked_by":                 contract.RevokedBy,
			"reason":                     contract.Reason,
		}
		if contract.PolicyReceiptID != "" {
			federationContractPolicyReceiptIDs = append(federationContractPolicyReceiptIDs, contract.PolicyReceiptID)
		}
		if contract.ActivatedAt != nil {
			data["activated_at"] = contract.ActivatedAt.UTC().Format(time.RFC3339Nano)
		}
		if contract.SuspendedAt != nil {
			data["suspended_at"] = contract.SuspendedAt.UTC().Format(time.RFC3339Nano)
		}
		if contract.ResumedAt != nil {
			data["resumed_at"] = contract.ResumedAt.UTC().Format(time.RFC3339Nano)
		}
		if contract.RevokedAt != nil {
			data["revoked_at"] = contract.RevokedAt.UTC().Format(time.RFC3339Nano)
		}
		ledger.AddRecord(evidence.Record{
			ID:        recordID,
			Type:      "trust",
			Action:    "secure_cell.federation_contract_state",
			Actor:     firstNonEmpty(contract.RevokedBy, contract.ActivatedBy, contract.CreatedBy, req.OwnerIdentity.AgentID()),
			Timestamp: secureCellFederationContractUpdatedAt(contract).UTC().Format(time.RFC3339Nano),
			Data:      data,
		})
	}
	for _, proposal := range run.result.FederationCounterproposals {
		recordID := fmt.Sprintf("%s-federation-counterproposal-%x", cellID(req), sha256.Sum256([]byte(proposal.ID)))
		federationCounterproposalRecordIDs = append(federationCounterproposalRecordIDs, recordID)
		data := map[string]string{
			"federation_counterproposal_id": proposal.ID,
			"federation_invitation_id":      proposal.InvitationID,
			"federation_organization_id":    proposal.OrganizationID,
			"sponsor_of_record":             proposal.SponsorOfRecord,
			"organization_name":             proposal.OrganizationName,
			"jurisdiction":                  proposal.Jurisdiction,
			"status":                        string(proposal.Status),
			"offered_session_scope_ids":     strings.Join(proposal.OfferedSessionScopeIDs, ","),
			"offered_data_classes":          strings.Join(proposal.OfferedDataClasses, ","),
			"offered_compute_zones":         strings.Join(proposal.OfferedComputeZones, ","),
			"offered_actions":               strings.Join(proposal.OfferedActions, ","),
			"negotiated_session_scope_ids":  strings.Join(proposal.NegotiatedSessionScopeIDs, ","),
			"negotiated_data_classes":       strings.Join(proposal.NegotiatedDataClasses, ","),
			"negotiated_compute_zones":      strings.Join(proposal.NegotiatedComputeZones, ","),
			"negotiated_actions":            strings.Join(proposal.NegotiatedActions, ","),
			"negotiation_diffs":             secureCellFederationPolicyDiffsSummary(proposal.NegotiationDiffs),
			"resource":                      proposal.Resource,
			"submitted_by":                  proposal.SubmittedBy,
			"approved_by":                   proposal.ApprovedBy,
			"rejected_by":                   proposal.RejectedBy,
			"superseded_by":                 proposal.SupersededBy,
			"reason":                        proposal.Reason,
		}
		if proposal.ApprovedAt != nil {
			data["approved_at"] = proposal.ApprovedAt.UTC().Format(time.RFC3339Nano)
		}
		if proposal.RejectedAt != nil {
			data["rejected_at"] = proposal.RejectedAt.UTC().Format(time.RFC3339Nano)
		}
		if proposal.SupersededAt != nil {
			data["superseded_at"] = proposal.SupersededAt.UTC().Format(time.RFC3339Nano)
		}
		ledger.AddRecord(evidence.Record{
			ID:        recordID,
			Type:      "trust",
			Action:    "secure_cell.federation_counterproposal_state",
			Actor:     firstNonEmpty(proposal.SupersededBy, proposal.RejectedBy, proposal.ApprovedBy, proposal.SubmittedBy, req.OwnerIdentity.AgentID()),
			Timestamp: secureCellFederationCounterproposalUpdatedAt(proposal).UTC().Format(time.RFC3339Nano),
			Data:      data,
		})
	}
	for _, response := range run.result.FederationIncidentResponses {
		recordID := fmt.Sprintf("%s-federation-incident-response-%x", cellID(req), sha256.Sum256([]byte(response.ID)))
		federationIncidentResponseRecordIDs = append(federationIncidentResponseRecordIDs, recordID)
		ackDueAt, ackStatus := secureCellFederationIncidentResponseStepDueAndStatus(response, SecureCellFederationIncidentPlaybookStepTypeAcknowledge)
		remediationDueAt, remediationStatus := secureCellFederationIncidentResponseStepDueAndStatus(response, SecureCellFederationIncidentPlaybookStepTypeRemediate)
		verificationDueAt, verificationStatus := secureCellFederationIncidentResponseStepDueAndStatus(response, SecureCellFederationIncidentPlaybookStepTypeVerify)
		data := map[string]string{
			"federation_incident_response_id":                response.ID,
			"federation_organization_id":                     response.OrganizationID,
			"federation_sponsor_of_record":                   response.SponsorOfRecord,
			"organization_name":                              response.OrganizationName,
			"federation_incident_response_source":            string(response.SourceType),
			"federation_incident_snapshot_id":                response.SourceSnapshotID,
			"federation_incident_bulletin_id":                response.SourceBulletinID,
			"federation_incident_id":                         response.IncidentID,
			"federation_incident_status":                     string(response.IncidentStatus),
			"federation_incident_severity":                   string(response.IncidentSeverity),
			"federation_incident_category":                   string(response.IncidentCategory),
			"federation_incident_summary":                    response.IncidentSummary,
			"federation_incident_description":                response.IncidentDescription,
			"federation_incident_response_status":            string(response.Status),
			"federation_incident_required_acknowledgement":   string(response.RequiredAcknowledgement),
			"federation_incident_expected_remediation_from":  string(response.ExpectedRemediationFrom),
			"federation_incident_verification_required_from": string(response.VerificationRequiredFrom),
			"federation_contract_ids":                        strings.Join(response.ContractIDs, ","),
			"federation_session_ids":                         strings.Join(response.SessionIDs, ","),
			"federation_thread_ids":                          strings.Join(response.ThreadIDs, ","),
			"federation_shared_output_ids":                   strings.Join(response.SharedOutputIDs, ","),
			"federation_session_exchange_ids":                strings.Join(response.SessionExchangeIDs, ","),
			"federation_incident_playbook_template":          response.PlaybookTemplate,
			"federation_incident_escalation_ladder_tier_ids": strings.Join(secureCellFederationEscalationTierIDs(response.EscalationLadder), ","),
			"federation_incident_escalation_targets":         strings.Join(secureCellFederationEscalationTierTargets(response.EscalationLadder), ","),
			"federation_incident_escalated_tier_ids":         strings.Join(response.EscalatedTierIDs, ","),
			"federation_incident_remediation_count":          fmt.Sprintf("%d", len(response.RemediationAttestations)),
			"federation_incident_verification_count":         fmt.Sprintf("%d", len(response.RemediationVerifications)),
			"federation_incident_report_count":               fmt.Sprintf("%d", len(response.IncidentReports)),
			"federation_incident_closure_attestation_count":  fmt.Sprintf("%d", len(response.ClosureAttestations)),
			"federation_incident_dispute_count":              fmt.Sprintf("%d", len(response.Disputes)),
			"federation_incident_playbook_step_count":        fmt.Sprintf("%d", len(response.PlaybookSteps)),
			"federation_incident_ack_status":                 string(ackStatus),
			"federation_incident_remediation_status":         string(remediationStatus),
			"federation_incident_verification_status":        string(verificationStatus),
			"federation_incident_last_verification_decision": string(secureCellLatestFederationIncidentVerificationDecision(response)),
			"federation_incident_closure_ready":              fmt.Sprintf("%t", secureCellFederationIncidentResponseClosureReady(response)),
		}
		if ackDueAt != nil {
			data["federation_incident_ack_due_at"] = ackDueAt.UTC().Format(time.RFC3339Nano)
		}
		if remediationDueAt != nil {
			data["federation_incident_remediation_due_at"] = remediationDueAt.UTC().Format(time.RFC3339Nano)
		}
		if verificationDueAt != nil {
			data["federation_incident_verification_due_at"] = verificationDueAt.UTC().Format(time.RFC3339Nano)
		}
		if response.AcknowledgedBy != "" {
			data["federation_incident_acknowledged_by"] = response.AcknowledgedBy
		}
		if response.AcknowledgedAt != nil {
			data["federation_incident_acknowledged_at"] = response.AcknowledgedAt.UTC().Format(time.RFC3339Nano)
		}
		if response.RemediatedBy != "" {
			data["federation_incident_remediated_by"] = response.RemediatedBy
		}
		if response.RemediatedAt != nil {
			data["federation_incident_remediated_at"] = response.RemediatedAt.UTC().Format(time.RFC3339Nano)
		}
		if response.VerifiedBy != "" {
			data["federation_incident_verified_by"] = response.VerifiedBy
		}
		if response.VerifiedAt != nil {
			data["federation_incident_verified_at"] = response.VerifiedAt.UTC().Format(time.RFC3339Nano)
		}
		if response.ClosedBy != "" {
			data["federation_incident_closed_by"] = response.ClosedBy
		}
		if response.ClosedAt != nil {
			data["federation_incident_closed_at"] = response.ClosedAt.UTC().Format(time.RFC3339Nano)
		}
		if response.LastDisputedBy != "" {
			data["federation_incident_last_disputed_by"] = response.LastDisputedBy
		}
		if response.LastDisputedAt != nil {
			data["federation_incident_last_disputed_at"] = response.LastDisputedAt.UTC().Format(time.RFC3339Nano)
		}
		if response.ReopenedBy != "" {
			data["federation_incident_reopened_by"] = response.ReopenedBy
		}
		if response.ReopenedAt != nil {
			data["federation_incident_reopened_at"] = response.ReopenedAt.UTC().Format(time.RFC3339Nano)
		}
		if response.ReopenReason != "" {
			data["federation_incident_reopen_reason"] = response.ReopenReason
		}
		ledger.AddRecord(evidence.Record{
			ID:        recordID,
			Type:      "trust",
			Action:    "secure_cell.federation_incident_response_state",
			Actor:     firstNonEmpty(response.ClosedBy, response.VerifiedBy, response.RemediatedBy, response.AcknowledgedBy, req.OwnerIdentity.AgentID()),
			Timestamp: response.UpdatedAt.UTC().Format(time.RFC3339Nano),
			Data:      data,
		})
		for _, attestation := range response.RemediationAttestations {
			attestationRecordID := fmt.Sprintf("%s-federation-incident-remediation-%x", cellID(req), sha256.Sum256([]byte(attestation.ID)))
			federationIncidentRemediationRecordIDs = append(federationIncidentRemediationRecordIDs, attestationRecordID)
			ledger.AddRecord(evidence.Record{
				ID:        attestationRecordID,
				Type:      "trust",
				Action:    "secure_cell.federation_incident_remediation_attestation",
				Actor:     firstNonEmpty(attestation.SubmittedBy, req.OwnerIdentity.AgentID()),
				Timestamp: attestation.CreatedAt.UTC().Format(time.RFC3339Nano),
				Data: map[string]string{
					"federation_incident_response_id":              response.ID,
					"federation_incident_remediation_id":           attestation.ID,
					"federation_organization_id":                   attestation.OrganizationID,
					"federation_sponsor_of_record":                 attestation.SponsorOfRecord,
					"federation_incident_id":                       attestation.IncidentID,
					"federation_incident_remediation_party":        string(attestation.AttestingParty),
					"federation_incident_remediation_summary":      attestation.Summary,
					"federation_incident_remediation_description":  attestation.Description,
					"federation_incident_remediation_evidence_ids": strings.Join(attestation.EvidenceIDs, ","),
					"policy_receipt_id":                            attestation.PolicyReceiptID,
					"policy_receipt_hash":                          attestation.PolicyReceiptHash,
					"seal_id":                                      attestation.SealID,
					"trace_link_id":                                attestation.TraceLinkID,
				},
			})
		}
		for _, verification := range response.RemediationVerifications {
			verificationRecordID := fmt.Sprintf("%s-federation-incident-verification-%x", cellID(req), sha256.Sum256([]byte(verification.ID)))
			federationIncidentVerificationRecordIDs = append(federationIncidentVerificationRecordIDs, verificationRecordID)
			ledger.AddRecord(evidence.Record{
				ID:        verificationRecordID,
				Type:      "trust",
				Action:    "secure_cell.federation_incident_remediation_verification",
				Actor:     firstNonEmpty(verification.SubmittedBy, req.OwnerIdentity.AgentID()),
				Timestamp: verification.CreatedAt.UTC().Format(time.RFC3339Nano),
				Data: map[string]string{
					"federation_incident_response_id":               response.ID,
					"federation_incident_verification_id":           verification.ID,
					"federation_organization_id":                    verification.OrganizationID,
					"federation_sponsor_of_record":                  verification.SponsorOfRecord,
					"federation_incident_id":                        verification.IncidentID,
					"federation_incident_verification_party":        string(verification.ReviewingParty),
					"federation_incident_verification_decision":     string(verification.Decision),
					"federation_verified_attestation_id":            verification.VerifiedAttestationID,
					"federation_incident_verification_summary":      verification.Summary,
					"federation_incident_verification_description":  verification.Description,
					"federation_incident_verification_evidence_ids": strings.Join(verification.EvidenceIDs, ","),
					"policy_receipt_id":                             verification.PolicyReceiptID,
					"policy_receipt_hash":                           verification.PolicyReceiptHash,
					"seal_id":                                       verification.SealID,
					"trace_link_id":                                 verification.TraceLinkID,
				},
			})
		}
		for _, report := range response.IncidentReports {
			reportRecordID := fmt.Sprintf("%s-federation-incident-report-%x", cellID(req), sha256.Sum256([]byte(report.ID)))
			federationIncidentReportRecordIDs = append(federationIncidentReportRecordIDs, reportRecordID)
			data := map[string]string{
				"federation_incident_response_id":                 response.ID,
				"federation_incident_report_id":                   report.ID,
				"federation_organization_id":                      report.OrganizationID,
				"federation_sponsor_of_record":                    report.SponsorOfRecord,
				"federation_incident_id":                          report.IncidentID,
				"federation_incident_report_party":                string(report.ReportingParty),
				"federation_incident_report_regulator":            report.Regulator,
				"federation_incident_report_jurisdiction":         report.Jurisdiction,
				"federation_incident_report_framework":            report.Framework,
				"federation_incident_report_type":                 report.ReportType,
				"federation_incident_report_status":               string(report.Status),
				"federation_incident_report_summary":              report.Summary,
				"federation_incident_report_description":          report.Description,
				"federation_incident_report_sections":             strings.Join(report.RequiredSections, ","),
				"federation_incident_report_evidence_ids":         strings.Join(report.EvidenceIDs, ","),
				"federation_incident_report_submission_reference": report.SubmissionReference,
				"federation_incident_report_ack_reference":        report.AcknowledgementReference,
				"submission_receipt_id":                           report.SubmissionReceiptID,
				"submission_receipt_hash":                         report.SubmissionReceiptHash,
				"submission_seal_id":                              report.SubmissionSealID,
				"submission_trace_link_id":                        report.SubmissionTraceLinkID,
				"acknowledgement_receipt_id":                      report.AcknowledgementReceiptID,
				"acknowledgement_receipt_hash":                    report.AcknowledgementReceiptHash,
				"acknowledgement_seal_id":                         report.AcknowledgementSealID,
				"acknowledgement_trace_link_id":                   report.AcknowledgementTraceLinkID,
			}
			if report.DueAt != nil {
				data["federation_incident_report_due_at"] = report.DueAt.UTC().Format(time.RFC3339Nano)
			}
			if report.SubmittedAt != nil {
				data["federation_incident_report_submitted_at"] = report.SubmittedAt.UTC().Format(time.RFC3339Nano)
			}
			if report.SubmittedBy != "" {
				data["federation_incident_report_submitted_by"] = report.SubmittedBy
			}
			if report.AcknowledgedAt != nil {
				data["federation_incident_report_acknowledged_at"] = report.AcknowledgedAt.UTC().Format(time.RFC3339Nano)
			}
			if report.AcknowledgedBy != "" {
				data["federation_incident_report_acknowledged_by"] = report.AcknowledgedBy
			}
			ledger.AddRecord(evidence.Record{
				ID:        reportRecordID,
				Type:      "trust",
				Action:    "secure_cell.federation_incident_report_state",
				Actor:     firstNonEmpty(report.AcknowledgedBy, report.SubmittedBy, report.CreatedBy, req.OwnerIdentity.AgentID()),
				Timestamp: report.UpdatedAt.UTC().Format(time.RFC3339Nano),
				Data:      data,
			})
		}
		for _, attestation := range response.ClosureAttestations {
			closureRecordID := fmt.Sprintf("%s-federation-incident-closure-%x", cellID(req), sha256.Sum256([]byte(attestation.ID)))
			federationIncidentVerificationRecordIDs = append(federationIncidentVerificationRecordIDs, closureRecordID)
			ledger.AddRecord(evidence.Record{
				ID:        closureRecordID,
				Type:      "trust",
				Action:    "secure_cell.federation_incident_closure_attestation",
				Actor:     firstNonEmpty(attestation.SubmittedBy, req.OwnerIdentity.AgentID()),
				Timestamp: attestation.CreatedAt.UTC().Format(time.RFC3339Nano),
				Data: map[string]string{
					"federation_incident_response_id":            response.ID,
					"federation_incident_closure_attestation_id": attestation.ID,
					"federation_organization_id":                 attestation.OrganizationID,
					"federation_sponsor_of_record":               attestation.SponsorOfRecord,
					"federation_incident_id":                     attestation.IncidentID,
					"federation_incident_closure_party":          string(attestation.AttestingParty),
					"federation_incident_closure_summary":        attestation.Summary,
					"federation_incident_closure_description":    attestation.Description,
					"federation_incident_closure_evidence_ids":   strings.Join(attestation.EvidenceIDs, ","),
					"policy_receipt_id":                          attestation.PolicyReceiptID,
					"policy_receipt_hash":                        attestation.PolicyReceiptHash,
					"seal_id":                                    attestation.SealID,
					"trace_link_id":                              attestation.TraceLinkID,
				},
			})
		}
		for _, dispute := range response.Disputes {
			disputeRecordID := fmt.Sprintf("%s-federation-incident-dispute-%x", cellID(req), sha256.Sum256([]byte(dispute.ID)))
			federationIncidentVerificationRecordIDs = append(federationIncidentVerificationRecordIDs, disputeRecordID)
			ledger.AddRecord(evidence.Record{
				ID:        disputeRecordID,
				Type:      "trust",
				Action:    "secure_cell.federation_incident_response_dispute",
				Actor:     firstNonEmpty(dispute.SubmittedBy, req.OwnerIdentity.AgentID()),
				Timestamp: dispute.CreatedAt.UTC().Format(time.RFC3339Nano),
				Data: map[string]string{
					"federation_incident_response_id":              response.ID,
					"federation_incident_dispute_id":               dispute.ID,
					"federation_organization_id":                   dispute.OrganizationID,
					"federation_sponsor_of_record":                 dispute.SponsorOfRecord,
					"federation_incident_id":                       dispute.IncidentID,
					"federation_incident_disputing_party":          string(dispute.DisputingParty),
					"federation_related_verification_id":           dispute.RelatedVerificationID,
					"federation_related_closure_id":                dispute.RelatedClosureID,
					"federation_incident_dispute_summary":          dispute.Summary,
					"federation_incident_dispute_description":      dispute.Description,
					"federation_incident_dispute_evidence_ids":     strings.Join(dispute.EvidenceIDs, ","),
					"federation_incident_dispute_reopened":         fmt.Sprintf("%t", dispute.Reopened),
					"federation_incident_reopened_response_status": string(dispute.ReopenedResponseStatus),
					"policy_receipt_id":                            dispute.PolicyReceiptID,
					"policy_receipt_hash":                          dispute.PolicyReceiptHash,
					"seal_id":                                      dispute.SealID,
					"trace_link_id":                                dispute.TraceLinkID,
				},
			})
		}
	}

	for _, session := range run.result.Sessions {
		recordID := fmt.Sprintf("%s-session-%x", cellID(req), sha256.Sum256([]byte(session.ID)))
		sessionEvidenceRecordIDs = append(sessionEvidenceRecordIDs, recordID)
		sessionThreads := threadsForSession(run.result.Threads, session.ID)
		sessionDecisions := decisionsForSession(run.result.Decisions, session.ID)
		data := map[string]string{
			"session_id":          session.ID,
			"session_name":        session.Name,
			"session_purpose":     session.Purpose,
			"session_status":      string(session.Status),
			"participant_dids":    strings.Join(session.ParticipantDIDs, ","),
			"data_classes":        strings.Join(session.DataClasses, ","),
			"started_by":          session.StartedBy,
			"shared_outputs":      strings.Join(session.SharedOutputIDs, ","),
			"shared_output_count": fmt.Sprintf("%d", len(session.SharedOutputIDs)),
			"exchange_count":      fmt.Sprintf("%d", len(session.ExchangeIDs)),
			"thread_count":        fmt.Sprintf("%d", len(sessionThreads)),
			"active_thread_count": fmt.Sprintf("%d", len(threadsByStatus(sessionThreads, SecureCellThreadStatusActive))),
			"decision_count":      fmt.Sprintf("%d", len(sessionDecisions)),
		}
		if session.PausedFromStatus != "" {
			data["paused_from_status"] = string(session.PausedFromStatus)
		}
		if session.QuarantinedAt != nil {
			data["quarantined_at"] = session.QuarantinedAt.UTC().Format(time.RFC3339Nano)
		}
		if session.ContainedBy != "" {
			data["contained_by"] = session.ContainedBy
		}
		if session.ClosedBy != "" {
			data["closed_by"] = session.ClosedBy
		}
		if session.ClosedAt != nil {
			data["closed_at"] = session.ClosedAt.UTC().Format(time.RFC3339Nano)
		}
		ledger.AddRecord(evidence.Record{
			ID:        recordID,
			Type:      "collaboration",
			Action:    "secure_cell.session_state",
			Actor:     firstNonEmpty(session.ClosedBy, session.StartedBy, req.OwnerIdentity.AgentID()),
			Timestamp: session.UpdatedAt.UTC().Format(time.RFC3339Nano),
			Data:      data,
		})
	}

	for _, thread := range run.result.Threads {
		recordID := fmt.Sprintf("%s-thread-%x", cellID(req), sha256.Sum256([]byte(thread.ID)))
		threadEvidenceRecordIDs = append(threadEvidenceRecordIDs, recordID)
		threadDecisions := decisionsForThread(run.result.Decisions, thread.ID)
		data := map[string]string{
			"thread_id":        thread.ID,
			"session_id":       thread.SessionID,
			"thread_name":      thread.Name,
			"thread_purpose":   thread.Purpose,
			"thread_status":    string(thread.Status),
			"participant_dids": strings.Join(thread.ParticipantDIDs, ","),
			"data_classes":     strings.Join(thread.DataClasses, ","),
			"started_by":       thread.StartedBy,
			"decision_ids":     strings.Join(thread.DecisionIDs, ","),
			"decision_count":   fmt.Sprintf("%d", len(threadDecisions)),
			"exchange_ids":     strings.Join(thread.ExchangeIDs, ","),
			"exchange_count":   fmt.Sprintf("%d", len(thread.ExchangeIDs)),
		}
		if thread.QuarantinedAt != nil {
			data["quarantined_at"] = thread.QuarantinedAt.UTC().Format(time.RFC3339Nano)
		}
		if thread.ContainedBy != "" {
			data["contained_by"] = thread.ContainedBy
		}
		if thread.ClosedBy != "" {
			data["closed_by"] = thread.ClosedBy
		}
		if thread.ClosedAt != nil {
			data["closed_at"] = thread.ClosedAt.UTC().Format(time.RFC3339Nano)
		}
		ledger.AddRecord(evidence.Record{
			ID:        recordID,
			Type:      "collaboration",
			Action:    "secure_cell.session_thread_state",
			Actor:     firstNonEmpty(thread.ClosedBy, thread.ContainedBy, thread.StartedBy, req.OwnerIdentity.AgentID()),
			Timestamp: thread.UpdatedAt.UTC().Format(time.RFC3339Nano),
			Data:      data,
		})
	}

	for _, decision := range run.result.Decisions {
		recordID := fmt.Sprintf("%s-decision-%x", cellID(req), sha256.Sum256([]byte(decision.ID)))
		decisionEvidenceRecordIDs = append(decisionEvidenceRecordIDs, recordID)
		containedOutputIDs := secureCellDecisionContainedSharedOutputIDs(run.result.SharedOutputs, decision.ID)
		containedExchangeIDs := secureCellDecisionContainedSessionExchangeIDs(run.result.SessionExchanges, decision.ID)
		data := map[string]string{
			"decision_id":                  decision.ID,
			"session_id":                   decision.SessionID,
			"thread_id":                    decision.ThreadID,
			"decision_title":               decision.Title,
			"decision_status":              string(decision.Status),
			"decision_classification":      decision.Classification,
			"decision_governance_template": decision.GovernanceTemplate,
			"approval_threshold":           fmt.Sprintf("%d", decisionApprovalThreshold(decision)),
			"approval_vote_count":          fmt.Sprintf("%d", len(decision.ApprovalVotes)),
			"comment_count":                fmt.Sprintf("%d", len(decision.Comments)),
			"delegation_count":             fmt.Sprintf("%d", len(decision.Delegations)),
			"outcome_count":                fmt.Sprintf("%d", len(decision.OutcomeIDs)),
			"proposed_by":                  decision.ProposedBy,
			"eligible_approver_dids":       strings.Join(decision.EligibleApproverDIDs, ","),
			"required_approver_roles":      strings.Join(decision.RequiredApproverRoles, ","),
			"allowed_vote_choices":         joinSecureCellDecisionVoteChoices(decision.AllowedVoteChoices),
			"rejector_roles":               strings.Join(decision.RejectorRoles, ","),
			"abstainer_roles":              strings.Join(decision.AbstainerRoles, ","),
			"reopen_roles":                 strings.Join(decision.ReopenRoles, ","),
			"escalation_ladder_tier_ids":   strings.Join(secureCellDecisionEscalationTierIDs(decision.EscalationLadder), ","),
			"escalation_ladder_targets":    strings.Join(secureCellDecisionEscalationTierTargets(decision.EscalationLadder), ","),
			"auto_escalate_to_did":         decision.AutoEscalateToDID,
			"related_exchange_ids":         strings.Join(decision.RelatedExchangeIDs, ","),
			"related_output_ids":           strings.Join(decision.RelatedOutputIDs, ","),
			"contained_output_ids":         strings.Join(containedOutputIDs, ","),
			"contained_exchange_ids":       strings.Join(containedExchangeIDs, ","),
			"outcome_ids":                  strings.Join(decision.OutcomeIDs, ","),
			"required_roles_missing":       strings.Join(secureCellDecisionMissingRequiredRoles(decision), ","),
		}
		if decision.Summary != "" {
			data["decision_summary"] = decision.Summary
		}
		if decision.QuarantinedFromStatus != "" {
			data["quarantined_from_status"] = string(decision.QuarantinedFromStatus)
		}
		if decision.ApprovedBy != "" {
			data["approved_by"] = decision.ApprovedBy
		}
		if decision.ApprovedAt != nil {
			data["approved_at"] = decision.ApprovedAt.UTC().Format(time.RFC3339Nano)
		}
		if decision.QuorumFailedBy != "" {
			data["quorum_failed_by"] = decision.QuorumFailedBy
		}
		if decision.QuorumFailedAt != nil {
			data["quorum_failed_at"] = decision.QuorumFailedAt.UTC().Format(time.RFC3339Nano)
		}
		if decision.EscalationDueAt != nil {
			data["escalation_due_at"] = decision.EscalationDueAt.UTC().Format(time.RFC3339Nano)
		}
		if decision.ResolutionDueAt != nil {
			data["resolution_due_at"] = decision.ResolutionDueAt.UTC().Format(time.RFC3339Nano)
		}
		if decision.QuarantinedAt != nil {
			data["quarantined_at"] = decision.QuarantinedAt.UTC().Format(time.RFC3339Nano)
		}
		if decision.ContainedBy != "" {
			data["contained_by"] = decision.ContainedBy
		}
		if decision.ClosedBy != "" {
			data["closed_by"] = decision.ClosedBy
		}
		if decision.ClosedAt != nil {
			data["closed_at"] = decision.ClosedAt.UTC().Format(time.RFC3339Nano)
		}
		ledger.AddRecord(evidence.Record{
			ID:        recordID,
			Type:      "governance",
			Action:    "secure_cell.thread_decision_state",
			Actor:     firstNonEmpty(decision.ClosedBy, decision.ContainedBy, decision.ApprovedBy, decision.QuorumFailedBy, decision.ProposedBy, req.OwnerIdentity.AgentID()),
			Timestamp: decision.UpdatedAt.UTC().Format(time.RFC3339Nano),
			Data:      data,
		})
		for _, vote := range decision.ApprovalVotes {
			voteRecordID := fmt.Sprintf("%s-decision-vote-%x", cellID(req), sha256.Sum256([]byte(vote.ID)))
			decisionVoteRecordIDs = append(decisionVoteRecordIDs, voteRecordID)
			ledger.AddRecord(evidence.Record{
				ID:        voteRecordID,
				Type:      "governance",
				Action:    "secure_cell.thread_decision_vote",
				Actor:     vote.ActorDID,
				Timestamp: vote.CreatedAt.UTC().Format(time.RFC3339Nano),
				Data: map[string]string{
					"decision_id":         decision.ID,
					"vote_id":             vote.ID,
					"actor_role":          vote.ActorRole,
					"vote_choice":         string(vote.Choice),
					"vote_reason":         vote.Reason,
					"policy_receipt_id":   vote.PolicyReceiptID,
					"policy_receipt_hash": vote.PolicyReceiptHash,
					"seal_id":             vote.SealID,
					"trace_link_id":       vote.TraceLinkID,
				},
			})
		}
		for _, comment := range decision.Comments {
			commentRecordID := fmt.Sprintf("%s-decision-comment-%x", cellID(req), sha256.Sum256([]byte(comment.ID)))
			decisionCommentRecordIDs = append(decisionCommentRecordIDs, commentRecordID)
			ledger.AddRecord(evidence.Record{
				ID:        commentRecordID,
				Type:      "collaboration",
				Action:    "secure_cell.thread_decision_comment",
				Actor:     comment.ActorDID,
				Timestamp: comment.CreatedAt.UTC().Format(time.RFC3339Nano),
				Data: map[string]string{
					"decision_id":         decision.ID,
					"comment_id":          comment.ID,
					"actor_role":          comment.ActorRole,
					"comment":             comment.Comment,
					"comment_reason":      comment.Reason,
					"policy_receipt_id":   comment.PolicyReceiptID,
					"policy_receipt_hash": comment.PolicyReceiptHash,
					"seal_id":             comment.SealID,
					"trace_link_id":       comment.TraceLinkID,
				},
			})
		}
		for _, delegation := range decision.Delegations {
			delegationRecordID := fmt.Sprintf("%s-decision-delegation-%x", cellID(req), sha256.Sum256([]byte(delegation.ID)))
			decisionDelegationRecordIDs = append(decisionDelegationRecordIDs, delegationRecordID)
			ledger.AddRecord(evidence.Record{
				ID:        delegationRecordID,
				Type:      "governance",
				Action:    "secure_cell.thread_decision_delegation",
				Actor:     delegation.FromActorDID,
				Timestamp: delegation.CreatedAt.UTC().Format(time.RFC3339Nano),
				Data: map[string]string{
					"decision_id":         decision.ID,
					"delegation_id":       delegation.ID,
					"mode":                string(delegation.Mode),
					"from_actor_role":     delegation.FromActorRole,
					"to_actor_did":        delegation.ToActorDID,
					"to_actor_role":       delegation.ToActorRole,
					"reason":              delegation.Reason,
					"policy_receipt_id":   delegation.PolicyReceiptID,
					"policy_receipt_hash": delegation.PolicyReceiptHash,
					"seal_id":             delegation.SealID,
					"trace_link_id":       delegation.TraceLinkID,
				},
			})
		}
	}

	for _, outcome := range run.result.DecisionOutcomes {
		outcomeRecordID := fmt.Sprintf("%s-decision-outcome-%x", cellID(req), sha256.Sum256([]byte(outcome.ID)))
		decisionOutcomeRecordIDs = append(decisionOutcomeRecordIDs, outcomeRecordID)
		ledger.AddRecord(evidence.Record{
			ID:        outcomeRecordID,
			Type:      "exchange",
			Action:    "secure_cell.thread_decision_outcome",
			Actor:     outcome.PublishedBy,
			Timestamp: outcome.CreatedAt.UTC().Format(time.RFC3339Nano),
			Data: map[string]string{
				"decision_id":          outcome.DecisionID,
				"outcome_id":           outcome.ID,
				"title":                outcome.Title,
				"summary":              outcome.Summary,
				"classification":       outcome.Classification,
				"outcome_type":         outcome.OutcomeType,
				"published_by_role":    outcome.PublishedByRole,
				"integrity_hash":       outcome.IntegrityHash,
				"related_output_ids":   strings.Join(outcome.RelatedOutputIDs, ","),
				"related_exchange_ids": strings.Join(outcome.RelatedExchangeIDs, ","),
				"policy_receipt_id":    outcome.PolicyReceiptID,
				"policy_receipt_hash":  outcome.PolicyReceiptHash,
				"seal_id":              outcome.SealID,
				"trace_link_id":        outcome.TraceLinkID,
			},
		})
	}

	for _, output := range run.result.SharedOutputs {
		recordID := fmt.Sprintf("%s-output-%x", cellID(req), sha256.Sum256([]byte(output.ID)))
		sharedOutputRecordIDs = append(sharedOutputRecordIDs, recordID)
		data := map[string]string{
			"shared_output_id":        output.ID,
			"session_id":              output.SessionID,
			"name":                    output.Name,
			"artifact_type":           output.ArtifactType,
			"classification":          output.Classification,
			"resource":                output.Resource,
			"integrity_hash":          output.IntegrityHash,
			"produced_by":             output.ProducedBy,
			"shared_with":             strings.Join(output.SharedWith, ","),
			"federation_contract_ids": strings.Join(output.FederationContractIDs, ","),
			"federation_org_ids":      strings.Join(output.FederationOrgIDs, ","),
			"custody_entries_total":   fmt.Sprintf("%d", len(output.ChainOfCustody)),
			"containment_status":      string(firstNonEmptyArtifactContainmentStatus(output.ContainmentStatus, SecureCellArtifactContainmentStatusActive)),
			"containment_decision_id": output.ContainmentDecisionID,
			"containment_source_type": output.ContainmentSourceType,
			"containment_source_id":   output.ContainmentSourceID,
		}
		if output.Summary != "" {
			data["summary"] = output.Summary
		}
		if output.PolicyReceiptID != "" {
			data["policy_receipt_id"] = output.PolicyReceiptID
			sharedOutputPolicyReceiptIDs = append(sharedOutputPolicyReceiptIDs, output.PolicyReceiptID)
		}
		if transition, ok := sharedOutputTransitions[output.ID]; ok {
			if transition.ExecutionSeal != nil {
				data["seal_id"] = transition.ExecutionSeal.SealID
				sharedOutputSealIDs = append(sharedOutputSealIDs, transition.ExecutionSeal.SealID)
			}
			if transition.TraceLink != nil {
				data["trace_link_id"] = transition.TraceLink.ID
				sharedOutputTraceLinkIDs = append(sharedOutputTraceLinkIDs, transition.TraceLink.ID)
			}
			if transition.PolicyReceipt != nil {
				data["policy_receipt_hash"] = transition.PolicyReceipt.ContentHash
			}
		}
		if len(output.ChainOfCustody) > 0 {
			data["custody_head_hash"] = output.ChainOfCustody[len(output.ChainOfCustody)-1].Hash
		}
		if output.ContainmentReceiptID != "" {
			data["containment_receipt_id"] = output.ContainmentReceiptID
			data["containment_receipt_hash"] = output.ContainmentReceiptHash
		}
		if output.ContainmentSealID != "" {
			data["containment_seal_id"] = output.ContainmentSealID
		}
		if output.ContainmentTraceLinkID != "" {
			data["containment_trace_link_id"] = output.ContainmentTraceLinkID
		}
		if output.ContainedBy != "" {
			data["contained_by"] = output.ContainedBy
		}
		if output.ContainedAt != nil {
			data["contained_at"] = output.ContainedAt.UTC().Format(time.RFC3339Nano)
		}
		if output.ReleasedBy != "" {
			data["released_by"] = output.ReleasedBy
		}
		if output.ReleasedAt != nil {
			data["released_at"] = output.ReleasedAt.UTC().Format(time.RFC3339Nano)
		}
		ledger.AddRecord(evidence.Record{
			ID:        recordID,
			Type:      "exchange",
			Action:    "secure_cell.shared_output",
			Actor:     output.ProducedBy,
			Timestamp: output.CreatedAt.UTC().Format(time.RFC3339Nano),
			Data:      data,
		})
	}

	for _, item := range run.result.SessionExchanges {
		recordID := fmt.Sprintf("%s-exchange-%x", cellID(req), sha256.Sum256([]byte(item.ID)))
		sessionExchangeRecordIDs = append(sessionExchangeRecordIDs, recordID)
		data := map[string]string{
			"session_exchange_id":     item.ID,
			"session_id":              item.SessionID,
			"thread_id":               item.ThreadID,
			"name":                    item.Name,
			"exchange_type":           item.ExchangeType,
			"classification":          item.Classification,
			"resource":                item.Resource,
			"integrity_hash":          item.IntegrityHash,
			"sent_by":                 item.SentBy,
			"recipients":              strings.Join(item.Recipients, ","),
			"federation_contract_ids": strings.Join(item.FederationContractIDs, ","),
			"federation_org_ids":      strings.Join(item.FederationOrgIDs, ","),
			"custody_entries_total":   fmt.Sprintf("%d", len(item.ChainOfCustody)),
			"containment_status":      string(firstNonEmptyArtifactContainmentStatus(item.ContainmentStatus, SecureCellArtifactContainmentStatusActive)),
			"containment_decision_id": item.ContainmentDecisionID,
			"containment_source_type": item.ContainmentSourceType,
			"containment_source_id":   item.ContainmentSourceID,
		}
		if item.Summary != "" {
			data["summary"] = item.Summary
		}
		if item.PolicyReceiptID != "" {
			data["policy_receipt_id"] = item.PolicyReceiptID
			sessionExchangePolicyReceiptIDs = append(sessionExchangePolicyReceiptIDs, item.PolicyReceiptID)
		}
		if transition, ok := sharedOutputTransitions[item.ID]; ok {
			if transition.ExecutionSeal != nil {
				data["seal_id"] = transition.ExecutionSeal.SealID
				sessionExchangeSealIDs = append(sessionExchangeSealIDs, transition.ExecutionSeal.SealID)
			}
			if transition.TraceLink != nil {
				data["trace_link_id"] = transition.TraceLink.ID
				sessionExchangeTraceLinkIDs = append(sessionExchangeTraceLinkIDs, transition.TraceLink.ID)
			}
			if transition.PolicyReceipt != nil {
				data["policy_receipt_hash"] = transition.PolicyReceipt.ContentHash
			}
		}
		if len(item.ChainOfCustody) > 0 {
			data["custody_head_hash"] = item.ChainOfCustody[len(item.ChainOfCustody)-1].Hash
		}
		if item.ContainmentReceiptID != "" {
			data["containment_receipt_id"] = item.ContainmentReceiptID
			data["containment_receipt_hash"] = item.ContainmentReceiptHash
		}
		if item.ContainmentSealID != "" {
			data["containment_seal_id"] = item.ContainmentSealID
		}
		if item.ContainmentTraceLinkID != "" {
			data["containment_trace_link_id"] = item.ContainmentTraceLinkID
		}
		if item.ContainedBy != "" {
			data["contained_by"] = item.ContainedBy
		}
		if item.ContainedAt != nil {
			data["contained_at"] = item.ContainedAt.UTC().Format(time.RFC3339Nano)
		}
		if item.ReleasedBy != "" {
			data["released_by"] = item.ReleasedBy
		}
		if item.ReleasedAt != nil {
			data["released_at"] = item.ReleasedAt.UTC().Format(time.RFC3339Nano)
		}
		ledger.AddRecord(evidence.Record{
			ID:        recordID,
			Type:      "exchange",
			Action:    "secure_cell.session_exchange",
			Actor:     item.SentBy,
			Timestamp: item.CreatedAt.UTC().Format(time.RFC3339Nano),
			Data:      data,
		})
		if item.ThreadID != "" {
			threadMessageRecordIDs = append(threadMessageRecordIDs, recordID)
			if item.PolicyReceiptID != "" {
				threadMessagePolicyReceiptIDs = append(threadMessagePolicyReceiptIDs, item.PolicyReceiptID)
			}
			if sealID := data["seal_id"]; sealID != "" {
				threadMessageSealIDs = append(threadMessageSealIDs, sealID)
			}
			if traceLinkID := data["trace_link_id"]; traceLinkID != "" {
				threadMessageTraceLinkIDs = append(threadMessageTraceLinkIDs, traceLinkID)
			}
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
	if len(federationLifecycleRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-01",
			ControlName: "Cross-Organization Federation",
			Description: "Cross-organization invitations and joins are governed as explicit policy-bound lifecycle transitions tied to accountable sponsor-of-record identities.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: federationLifecycleRecordIDs,
			},
			Metadata: map[string]string{
				"federation_organizations_total":    fmt.Sprintf("%d", len(run.result.FederationOrganizations)),
				"federation_invitations_total":      fmt.Sprintf("%d", len(run.result.FederationInvitations)),
				"federation_counterproposals_total": fmt.Sprintf("%d", len(run.result.FederationCounterproposals)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationCounterproposalRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-03",
			ControlName: "Federation Negotiation Governance",
			Description: "Cross-organization invitations can be counterproposed, approved, rejected, and replayed as policy-bound negotiation history before activation.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: federationCounterproposalRecordIDs,
			},
			Metadata: map[string]string{
				"federation_counterproposals_total":      fmt.Sprintf("%d", len(run.result.FederationCounterproposals)),
				"federation_counterproposals_pending":    fmt.Sprintf("%d", len(secureCellFederationCounterproposalsByStatus(run.result.FederationCounterproposals, SecureCellFederationCounterproposalStatusPending))),
				"federation_counterproposals_approved":   fmt.Sprintf("%d", len(secureCellFederationCounterproposalsByStatus(run.result.FederationCounterproposals, SecureCellFederationCounterproposalStatusApproved))),
				"federation_counterproposals_rejected":   fmt.Sprintf("%d", len(secureCellFederationCounterproposalsByStatus(run.result.FederationCounterproposals, SecureCellFederationCounterproposalStatusRejected))),
				"federation_counterproposals_superseded": fmt.Sprintf("%d", len(secureCellFederationCounterproposalsByStatus(run.result.FederationCounterproposals, SecureCellFederationCounterproposalStatusSuperseded))),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationContractRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-02",
			ControlName: "Federated Exchange Contract Enforcement",
			Description: "Accepted federation invitations mint replayable collaboration contracts that scope which sessions, data classes, and outbound exchange actions are authorized for cross-organization traffic.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs:        federationContractRecordIDs,
				PolicyReceiptIDs: federationContractPolicyReceiptIDs,
			},
			Metadata: map[string]string{
				"federation_contracts_total":          fmt.Sprintf("%d", len(run.result.FederationContracts)),
				"federation_contracts_active":         fmt.Sprintf("%d", len(secureCellFederationContractsByStatus(run.result.FederationContracts, SecureCellFederationContractStatusActive))),
				"federation_contracts_suspended":      fmt.Sprintf("%d", len(secureCellFederationContractsByStatus(run.result.FederationContracts, SecureCellFederationContractStatusSuspended))),
				"federation_contracts_revoked":        fmt.Sprintf("%d", len(secureCellFederationContractsByStatus(run.result.FederationContracts, SecureCellFederationContractStatusRevoked))),
				"federation_contract_revisions_total": fmt.Sprintf("%d", len(run.result.FederationContracts)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationCounterpartyAssuranceRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-04",
			ControlName: "Reciprocal Federation Assurance",
			Description: "Counterparty federation posture bundles are imported, verified, and preserved as policy-bound reciprocal assurance evidence before continued cross-organization collaboration.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: federationCounterpartyAssuranceRecordIDs,
			},
			Metadata: map[string]string{
				"federation_counterparty_assurance_total":    fmt.Sprintf("%d", len(run.result.FederationCounterpartyAssurance)),
				"federation_counterparty_assurance_verified": fmt.Sprintf("%d", len(secureCellFederationCounterpartyAssuranceByStatus(run.result.FederationCounterpartyAssurance, SecureCellFederationCounterpartyAssuranceStatusVerified))),
				"federation_counterparty_assurance_stale":    fmt.Sprintf("%d", len(secureCellFederationCounterpartyAssuranceByStatus(run.result.FederationCounterpartyAssurance, SecureCellFederationCounterpartyAssuranceStatusStale))),
				"federation_counterparty_assurance_expired":  fmt.Sprintf("%d", len(secureCellFederationCounterpartyAssuranceByStatus(run.result.FederationCounterpartyAssurance, SecureCellFederationCounterpartyAssuranceStatusExpired))),
				"federation_counterparty_assurance_invalid":  fmt.Sprintf("%d", len(secureCellFederationCounterpartyAssuranceByStatus(run.result.FederationCounterpartyAssurance, SecureCellFederationCounterpartyAssuranceStatusInvalid))),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentRecordIDs) > 0 || len(federationCounterpartyIncidentRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-05",
			ControlName: "Federation Incident Control Plane",
			Description: "Federation incidents, signed bulletins, imported counterparty incident state, and fail-closed containment actions are preserved as governed collaboration evidence.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append(append(append([]string(nil), federationIncidentRecordIDs...), federationCounterpartyIncidentRecordIDs...), federationIncidentActionRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incidents_total":                 fmt.Sprintf("%d", len(run.result.FederationIncidents)),
				"federation_incidents_open":                  fmt.Sprintf("%d", len(secureCellFederationIncidentsByStatus(run.result.FederationIncidents, SecureCellFederationIncidentStatusOpen))),
				"federation_incidents_resolved":              fmt.Sprintf("%d", len(secureCellFederationIncidentsByStatus(run.result.FederationIncidents, SecureCellFederationIncidentStatusResolved))),
				"federation_counterparty_incidents_total":    fmt.Sprintf("%d", len(run.result.FederationCounterpartyIncidents)),
				"federation_counterparty_incidents_verified": fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentsByStatus(run.result.FederationCounterpartyIncidents, SecureCellFederationCounterpartyIncidentStatusVerified))),
				"federation_counterparty_incidents_stale":    fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentsByStatus(run.result.FederationCounterpartyIncidents, SecureCellFederationCounterpartyIncidentStatusStale))),
				"federation_counterparty_incidents_expired":  fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentsByStatus(run.result.FederationCounterpartyIncidents, SecureCellFederationCounterpartyIncidentStatusExpired))),
				"federation_counterparty_incidents_invalid":  fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentsByStatus(run.result.FederationCounterpartyIncidents, SecureCellFederationCounterpartyIncidentStatusInvalid))),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentResponseRecordIDs) > 0 || len(federationIncidentResponseActionRecordIDs) > 0 || len(federationIncidentRemediationRecordIDs) > 0 || len(federationIncidentVerificationRecordIDs) > 0 || len(federationIncidentReportRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-06",
			ControlName: "Federation Incident Command Fabric",
			Description: "Cross-organization incident acknowledgements, escalations, timed playbooks, reporting obligations, remediation attestations, opposite-party verification, closure attestations, and disputes are preserved as bilateral command evidence instead of ad hoc containment logs.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append(
					append(
						append(
							append(
								append([]string(nil), federationIncidentResponseRecordIDs...),
								federationIncidentResponseActionRecordIDs...,
							),
							federationIncidentReportRecordIDs...,
						),
						federationIncidentRemediationRecordIDs...,
					),
					federationIncidentVerificationRecordIDs...,
				),
			},
			Metadata: map[string]string{
				"federation_incident_responses_total":                    fmt.Sprintf("%d", len(run.result.FederationIncidentResponses)),
				"federation_incident_responses_pending_local_ack":        fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusPendingLocalAck))),
				"federation_incident_responses_pending_counterparty_ack": fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusPendingCounterpartyAck))),
				"federation_incident_responses_acknowledged":             fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusAcknowledged))),
				"federation_incident_responses_escalated":                fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusEscalated))),
				"federation_incident_responses_remediating":              fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusRemediating))),
				"federation_incident_responses_remediated":               fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusRemediated))),
				"federation_incident_responses_closed":                   fmt.Sprintf("%d", len(secureCellFederationIncidentResponsesByStatus(run.result.FederationIncidentResponses, SecureCellFederationIncidentResponseStatusClosed))),
				"federation_incident_directives_total":                   fmt.Sprintf("%d", secureCellFederationIncidentResponseDirectiveTotal(run.result.FederationIncidentResponses)),
				"federation_incident_reports_total":                      fmt.Sprintf("%d", secureCellFederationIncidentResponseReportTotal(run.result.FederationIncidentResponses)),
				"federation_incident_remediations_total":                 fmt.Sprintf("%d", secureCellFederationIncidentResponseRemediationTotal(run.result.FederationIncidentResponses)),
				"federation_incident_verifications_total":                fmt.Sprintf("%d", secureCellFederationIncidentResponseVerificationTotal(run.result.FederationIncidentResponses)),
				"federation_incident_closure_attestations_total":         fmt.Sprintf("%d", secureCellFederationIncidentResponseClosureAttestationTotal(run.result.FederationIncidentResponses)),
				"federation_incident_disputes_total":                     fmt.Sprintf("%d", secureCellFederationIncidentResponseDisputeTotal(run.result.FederationIncidentResponses)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationCounterpartyIncidentReportRecordIDs) > 0 || len(federationIncidentReportRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-07",
			ControlName: "Reciprocal Federation Incident Reporting",
			Description: "Signed cross-organization incident report bundles are imported, verified, and reconciled against local reporting obligations so bilateral incident closure depends on aligned report posture instead of disconnected local logs.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append(append([]string(nil), federationIncidentReportRecordIDs...), federationCounterpartyIncidentReportRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_reports_total":                            fmt.Sprintf("%d", secureCellFederationIncidentResponseReportTotal(run.result.FederationIncidentResponses)),
				"federation_counterparty_incident_reports_total":               fmt.Sprintf("%d", len(run.result.FederationCounterpartyIncidentReports)),
				"federation_counterparty_incident_reports_verified":            fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentReportsByStatus(run.result.FederationCounterpartyIncidentReports, SecureCellFederationCounterpartyIncidentReportStatusVerified))),
				"federation_counterparty_incident_reports_stale":               fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentReportsByStatus(run.result.FederationCounterpartyIncidentReports, SecureCellFederationCounterpartyIncidentReportStatusStale))),
				"federation_counterparty_incident_reports_expired":             fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentReportsByStatus(run.result.FederationCounterpartyIncidentReports, SecureCellFederationCounterpartyIncidentReportStatusExpired))),
				"federation_counterparty_incident_reports_invalid":             fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentReportsByStatus(run.result.FederationCounterpartyIncidentReports, SecureCellFederationCounterpartyIncidentReportStatusInvalid))),
				"federation_incident_report_reconciliations_total":             fmt.Sprintf("%d", len(secureCellFederationIncidentReportReconciliationsFromRun(run))),
				"federation_incident_report_reconciliations_aligned":           fmt.Sprintf("%d", secureCellFederationIncidentReportReconciliationStatusCount(secureCellFederationIncidentReportReconciliationsFromRun(run), SecureCellFederationIncidentReportReconciliationStatusAligned)),
				"federation_incident_report_reconciliations_divergent":         fmt.Sprintf("%d", secureCellFederationIncidentReportReconciliationDivergentCount(secureCellFederationIncidentReportReconciliationsFromRun(run))),
				"federation_incident_report_reconciliations_local_only":        fmt.Sprintf("%d", secureCellFederationIncidentReportReconciliationStatusCount(secureCellFederationIncidentReportReconciliationsFromRun(run), SecureCellFederationIncidentReportReconciliationStatusLocalOnly)),
				"federation_incident_report_reconciliations_counterparty_only": fmt.Sprintf("%d", secureCellFederationIncidentReportReconciliationStatusCount(secureCellFederationIncidentReportReconciliationsFromRun(run), SecureCellFederationIncidentReportReconciliationStatusCounterpartyOnly)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationCounterpartyIncidentReportAmendmentRecordIDs) > 0 || len(federationIncidentReportAmendmentRecordIDs) > 0 {
		reconciliations := secureCellFederationIncidentReportAmendmentReconciliationsFromRun(run)
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-09",
			ControlName: "Reciprocal Federation Incident Report Amendments",
			Description: "Signed cross-organization incident report amendment bundles are imported, verified, and reconciled against local amendment posture so bilateral filing updates stay aligned after one side revises a regulator submission.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append(append([]string(nil), federationIncidentReportAmendmentRecordIDs...), federationCounterpartyIncidentReportAmendmentRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_report_amendments_total":                            fmt.Sprintf("%d", secureCellFederationIncidentResponseReportAmendmentTotal(run.result.FederationIncidentResponses)),
				"federation_counterparty_incident_report_amendments_total":               fmt.Sprintf("%d", len(run.result.FederationCounterpartyIncidentReportAmendments)),
				"federation_counterparty_incident_report_amendments_verified":            fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentReportAmendmentsByStatus(run.result.FederationCounterpartyIncidentReportAmendments, SecureCellFederationCounterpartyIncidentReportAmendmentStatusVerified))),
				"federation_counterparty_incident_report_amendments_stale":               fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentReportAmendmentsByStatus(run.result.FederationCounterpartyIncidentReportAmendments, SecureCellFederationCounterpartyIncidentReportAmendmentStatusStale))),
				"federation_counterparty_incident_report_amendments_expired":             fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentReportAmendmentsByStatus(run.result.FederationCounterpartyIncidentReportAmendments, SecureCellFederationCounterpartyIncidentReportAmendmentStatusExpired))),
				"federation_counterparty_incident_report_amendments_invalid":             fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentReportAmendmentsByStatus(run.result.FederationCounterpartyIncidentReportAmendments, SecureCellFederationCounterpartyIncidentReportAmendmentStatusInvalid))),
				"federation_incident_report_amendment_reconciliations_total":             fmt.Sprintf("%d", len(reconciliations)),
				"federation_incident_report_amendment_reconciliations_aligned":           fmt.Sprintf("%d", secureCellFederationIncidentReportAmendmentReconciliationStatusCount(reconciliations, SecureCellFederationIncidentReportAmendmentReconciliationStatusAligned)),
				"federation_incident_report_amendment_reconciliations_divergent":         fmt.Sprintf("%d", secureCellFederationIncidentReportAmendmentReconciliationDivergentCount(reconciliations)),
				"federation_incident_report_amendment_reconciliations_local_only":        fmt.Sprintf("%d", secureCellFederationIncidentReportAmendmentReconciliationStatusCount(reconciliations, SecureCellFederationIncidentReportAmendmentReconciliationStatusLocalOnly)),
				"federation_incident_report_amendment_reconciliations_counterparty_only": fmt.Sprintf("%d", secureCellFederationIncidentReportAmendmentReconciliationStatusCount(reconciliations, SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyOnly)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentReportAmendmentReconciliationRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-10",
			ControlName: "Governed Bilateral Amendment Reconciliation",
			Description: "Imported counterparty incident report amendments are not merely compared; bilateral filing revisions are explicitly acknowledged, disputed, and resolved as evidence-bearing cross-organization governance.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentReportAmendmentReconciliationRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_report_amendment_reconciliation_actions_total":      fmt.Sprintf("%d", len(federationIncidentReportAmendmentReconciliationRecordIDs)),
				"federation_incident_report_amendment_reconciliations_total":             fmt.Sprintf("%d", len(secureCellFederationIncidentReportAmendmentReconciliationsFromRun(run))),
				"federation_incident_report_amendment_reconciliations_aligned":           fmt.Sprintf("%d", secureCellFederationIncidentReportAmendmentReconciliationStatusCount(secureCellFederationIncidentReportAmendmentReconciliationsFromRun(run), SecureCellFederationIncidentReportAmendmentReconciliationStatusAligned)),
				"federation_incident_report_amendment_reconciliations_divergent":         fmt.Sprintf("%d", secureCellFederationIncidentReportAmendmentReconciliationDivergentCount(secureCellFederationIncidentReportAmendmentReconciliationsFromRun(run))),
				"federation_incident_report_amendment_reconciliations_counterparty_only": fmt.Sprintf("%d", secureCellFederationIncidentReportAmendmentReconciliationStatusCount(secureCellFederationIncidentReportAmendmentReconciliationsFromRun(run), SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyOnly)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentReportAmendmentReconciliationAttestationRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-11",
			ControlName: "Bilateral Amendment Dispute Coordination",
			Description: "Disputed bilateral incident report amendment reconciliations carry counterparty acknowledgements, correction attestations, resolution attestations, and governed escalations so cross-organization filing corrections remain replayable and enforceable.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentReportAmendmentReconciliationAttestationRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_report_amendment_reconciliation_coordination_actions_total": fmt.Sprintf("%d", len(federationIncidentReportAmendmentReconciliationAttestationRecordIDs)),
				"federation_incident_report_amendment_reconciliations_total":                     fmt.Sprintf("%d", len(secureCellFederationIncidentReportAmendmentReconciliationsFromRun(run))),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentDirectiveRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-12",
			ControlName: "Bilateral Incident Directive Governance",
			Description: "Cross-organization incident directives are issued, acknowledged, completed, and reviewer-verified as timed evidence-bearing work orders instead of informal coordination tasks.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentDirectiveRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_directives_total":        fmt.Sprintf("%d", secureCellFederationIncidentResponseDirectiveTotal(run.result.FederationIncidentResponses)),
				"federation_incident_directives_issued":       fmt.Sprintf("%d", secureCellFederationIncidentResponseDirectiveStatusTotal(run.result.FederationIncidentResponses, SecureCellFederationIncidentDirectiveStatusIssued)),
				"federation_incident_directives_acknowledged": fmt.Sprintf("%d", secureCellFederationIncidentResponseDirectiveStatusTotal(run.result.FederationIncidentResponses, SecureCellFederationIncidentDirectiveStatusAcknowledged)),
				"federation_incident_directives_completed":    fmt.Sprintf("%d", secureCellFederationIncidentResponseDirectiveStatusTotal(run.result.FederationIncidentResponses, SecureCellFederationIncidentDirectiveStatusCompleted)),
				"federation_incident_directives_verified":     fmt.Sprintf("%d", secureCellFederationIncidentResponseDirectiveStatusTotal(run.result.FederationIncidentResponses, SecureCellFederationIncidentDirectiveStatusVerified)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentDirectiveExtensionRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-13",
			ControlName: "Bilateral Directive Exception Governance",
			Description: "Bilateral incident directive deadline extensions are requested, approved, rejected, disputed, and resolved as evidence-bearing exception governance instead of out-of-band deadline changes.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentDirectiveExtensionRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_directive_extensions_total":          fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionTotal(run.result.FederationIncidentResponses)),
				"federation_incident_directive_extensions_pending_review": fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionStatusCount(run.result.FederationIncidentResponses, SecureCellFederationIncidentDirectiveExtensionStatusPendingReview)),
				"federation_incident_directive_extensions_approved":       fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionStatusCount(run.result.FederationIncidentResponses, SecureCellFederationIncidentDirectiveExtensionStatusApproved)),
				"federation_incident_directive_extensions_rejected":       fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionStatusCount(run.result.FederationIncidentResponses, SecureCellFederationIncidentDirectiveExtensionStatusRejected)),
				"federation_incident_directive_extensions_disputed":       fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionStatusCount(run.result.FederationIncidentResponses, SecureCellFederationIncidentDirectiveExtensionStatusDisputed)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentDirectiveExtensionDisputeRecordIDs) > 0 || len(federationIncidentDirectiveExtensionAutomationRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-14",
			ControlName: "Directive Exception Dispute And Timed Review Automation",
			Description: "Bilateral directive exception decisions can be challenged, resolved, and automatically escalated or fail-closed when review or dispute deadlines lapse.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append(append([]string(nil), federationIncidentDirectiveExtensionDisputeRecordIDs...), federationIncidentDirectiveExtensionAutomationRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_directive_extension_disputes_total":           fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionDisputeCount(run.result.FederationIncidentResponses)),
				"federation_incident_directive_extension_pending_disputes_total":   fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionPendingDisputeCountAll(run.result.FederationIncidentResponses)),
				"federation_incident_directive_extension_dispute_records_total":    fmt.Sprintf("%d", len(federationIncidentDirectiveExtensionDisputeRecordIDs)),
				"federation_incident_directive_extension_automation_records_total": fmt.Sprintf("%d", len(federationIncidentDirectiveExtensionAutomationRecordIDs)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentDirectiveExtensionAppealRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-15",
			ControlName: "Directive Exception Appeal And Ratification Governance",
			Description: "Resolved bilateral directive exception disputes can be appealed to a cross-organization board, ruled through thresholded votes, and reciprocally acknowledged before the final exception posture is enforced.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentDirectiveExtensionAppealRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_directive_extension_appeals_total":                         fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealCount(run.result.FederationIncidentResponses)),
				"federation_incident_directive_extension_pending_appeals_total":                 fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionPendingAppealCount(run.result.FederationIncidentResponses)),
				"federation_incident_directive_extension_appeal_records_total":                  fmt.Sprintf("%d", len(federationIncidentDirectiveExtensionAppealRecordIDs)),
				"federation_incident_directive_extension_appeal_acknowledged_enforcement_total": fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealStatusCount(run.result.FederationIncidentResponses, SecureCellFederationIncidentDirectiveExtensionAppealStatusEnforcementAcknowledged)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentDirectiveExtensionAppealAutomationRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-16",
			ControlName: "Timed Appeal Board Supervision And Enforcement",
			Description: "Bilateral directive-exception appeals are not passive board records; overdue board reviews and overdue enforcement acknowledgements are automatically delegated, escalated, or fail-closed as evidence-bearing governance actions.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentDirectiveExtensionAppealAutomationRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_directive_extension_appeals_total":                         fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealCount(run.result.FederationIncidentResponses)),
				"federation_incident_directive_extension_pending_appeals_total":                 fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionPendingAppealCount(run.result.FederationIncidentResponses)),
				"federation_incident_directive_extension_appeal_automation_records_total":       fmt.Sprintf("%d", len(federationIncidentDirectiveExtensionAppealAutomationRecordIDs)),
				"federation_incident_directive_extension_appeals_pending_board_review_total":    fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealStatusCount(run.result.FederationIncidentResponses, SecureCellFederationIncidentDirectiveExtensionAppealStatusPendingBoardReview)),
				"federation_incident_directive_extension_appeals_pending_enforcement_ack_total": fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealStatusCount(run.result.FederationIncidentResponses, SecureCellFederationIncidentDirectiveExtensionAppealStatusRatified)+secureCellFederationIncidentDirectiveExtensionAppealStatusCount(run.result.FederationIncidentResponses, SecureCellFederationIncidentDirectiveExtensionAppealStatusOverturned)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if secureCellFederationIncidentDirectiveExtensionAppealRecusalCount(run.result.FederationIncidentResponses) > 0 || secureCellFederationIncidentDirectiveExtensionAppealRehearingCount(run.result.FederationIncidentResponses) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-17",
			ControlName: "Appeal Board Conflict And Rehearing Governance",
			Description: "Bilateral directive-exception appeals can survive reviewer conflicts and challenged rulings through evidence-bearing recusals and governed rehearing revisions rather than ad-hoc board resets.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentDirectiveExtensionAppealRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_directive_extension_appeal_recusals_total":   fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealRecusalCount(run.result.FederationIncidentResponses)),
				"federation_incident_directive_extension_appeal_rehearings_total": fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealRehearingCount(run.result.FederationIncidentResponses)),
				"federation_incident_directive_extension_appeal_records_total":    fmt.Sprintf("%d", len(federationIncidentDirectiveExtensionAppealRecordIDs)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationCounterpartyIncidentDirectiveExtensionAppealRecordIDs) > 0 {
		reconciliations := secureCellFederationIncidentDirectiveExtensionAppealReconciliationsFromRun(run)
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-18",
			ControlName: "Reciprocal Appeal Bundle Exchange",
			Description: "Signed bilateral directive-exception appeal bundles are imported, verified, and reconciled against the local appeal chain so rehearings and enforcement posture remain cross-organization replayable instead of siloed local board state.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append(append([]string(nil), federationIncidentDirectiveExtensionAppealRecordIDs...), federationCounterpartyIncidentDirectiveExtensionAppealRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_directive_extension_appeals_total":                            fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealCount(run.result.FederationIncidentResponses)),
				"federation_counterparty_incident_directive_extension_appeals_total":               fmt.Sprintf("%d", len(run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals)),
				"federation_counterparty_incident_directive_extension_appeals_verified":            fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentDirectiveExtensionAppealsByStatus(run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals, SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusVerified))),
				"federation_counterparty_incident_directive_extension_appeals_stale":               fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentDirectiveExtensionAppealsByStatus(run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals, SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusStale))),
				"federation_counterparty_incident_directive_extension_appeals_expired":             fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentDirectiveExtensionAppealsByStatus(run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals, SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusExpired))),
				"federation_counterparty_incident_directive_extension_appeals_invalid":             fmt.Sprintf("%d", len(secureCellFederationCounterpartyIncidentDirectiveExtensionAppealsByStatus(run.result.FederationCounterpartyIncidentDirectiveExtensionAppeals, SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatusInvalid))),
				"federation_incident_directive_extension_appeal_reconciliations_total":             fmt.Sprintf("%d", len(reconciliations)),
				"federation_incident_directive_extension_appeal_reconciliations_aligned":           fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusCount(reconciliations, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusAligned)),
				"federation_incident_directive_extension_appeal_reconciliations_divergent":         fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationDivergentCount(reconciliations)),
				"federation_incident_directive_extension_appeal_reconciliations_local_only":        fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusCount(reconciliations, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusLocalOnly)),
				"federation_incident_directive_extension_appeal_reconciliations_counterparty_only": fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusCount(reconciliations, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusCounterpartyOnly)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentDirectiveExtensionAppealReconciliationRecordIDs) > 0 {
		reconciliations := secureCellFederationIncidentDirectiveExtensionAppealReconciliationsFromRun(run)
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-19",
			ControlName: "Governed Bilateral Appeal Reconciliation",
			Description: "Imported directive-exception appeal posture is not merely compared; bilateral appeal alignment is explicitly acknowledged, disputed, and resolved as evidence-bearing cross-organization governance.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentDirectiveExtensionAppealReconciliationRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_directive_extension_appeal_reconciliation_actions_total":      fmt.Sprintf("%d", len(federationIncidentDirectiveExtensionAppealReconciliationRecordIDs)),
				"federation_incident_directive_extension_appeal_reconciliations_total":             fmt.Sprintf("%d", len(reconciliations)),
				"federation_incident_directive_extension_appeal_reconciliations_aligned":           fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusCount(reconciliations, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusAligned)),
				"federation_incident_directive_extension_appeal_reconciliations_divergent":         fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationDivergentCount(reconciliations)),
				"federation_incident_directive_extension_appeal_reconciliations_counterparty_only": fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusCount(reconciliations, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusCounterpartyOnly)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentDirectiveExtensionAppealReconciliationAttestationRecordIDs) > 0 {
		reconciliations := secureCellFederationIncidentDirectiveExtensionAppealReconciliationsFromRun(run)
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-20",
			ControlName: "Appeal Reconciliation Counterparty Coordination",
			Description: "Disputed directive-exception appeal reconciliations carry bilateral acknowledgement, correction, and resolution attestations so counterparty remediation is part of the signed governance trail.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentDirectiveExtensionAppealReconciliationAttestationRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_directive_extension_appeal_reconciliation_counterparty_attestations_total": fmt.Sprintf("%d", len(federationIncidentDirectiveExtensionAppealReconciliationAttestationRecordIDs)),
				"federation_incident_directive_extension_appeal_reconciliations_total":                          fmt.Sprintf("%d", len(reconciliations)),
				"federation_incident_directive_extension_appeal_reconciliations_disputed":                       fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusCount(reconciliations, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusDivergent)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentDirectiveExtensionAppealReconciliationAutomationRecordIDs) > 0 {
		reconciliations := secureCellFederationIncidentDirectiveExtensionAppealReconciliationsFromRun(run)
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-21",
			ControlName: "Appeal Reconciliation Timed Supervision",
			Description: "Bilateral appeal reconciliations are actively supervised with timed dispute creation, counterparty escalation, and fail-closed contract suspension when cross-organization coordination stalls.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentDirectiveExtensionAppealReconciliationAutomationRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_directive_extension_appeal_reconciliation_automation_actions_total": fmt.Sprintf("%d", len(federationIncidentDirectiveExtensionAppealReconciliationAutomationRecordIDs)),
				"federation_incident_directive_extension_appeal_reconciliations_total":                   fmt.Sprintf("%d", len(reconciliations)),
				"federation_incident_directive_extension_appeal_reconciliations_disputed":                fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusCount(reconciliations, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusDivergent)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentDirectiveExtensionAppealReconciliationChallengeRecordIDs) > 0 {
		challenges := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengesFromRun(run)
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-22",
			ControlName: "Appeal Reconciliation Challenge Board Governance",
			Description: "Disputed or resolved bilateral appeal reconciliations can be escalated into a thresholded challenge board with signed votes and rulings, so cross-organization challenge review stays governed instead of reverting to ad hoc escalation.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentDirectiveExtensionAppealReconciliationChallengeRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_directive_extension_appeal_reconciliation_challenge_actions_total": fmt.Sprintf("%d", len(federationIncidentDirectiveExtensionAppealReconciliationChallengeRecordIDs)),
				"federation_incident_directive_extension_appeal_reconciliation_challenges_total":        fmt.Sprintf("%d", len(challenges)),
				"federation_incident_directive_extension_appeal_reconciliation_challenges_pending":      fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusCount(challenges, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview)),
				"federation_incident_directive_extension_appeal_reconciliation_challenges_ratified":     fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusCount(challenges, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusRatified)),
				"federation_incident_directive_extension_appeal_reconciliation_challenges_overturned":   fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusCount(challenges, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusOverturned)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationRecordIDs) > 0 {
		challenges := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengesFromRun(run)
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-23",
			ControlName: "Appeal Reconciliation Challenge Timed Supervision",
			Description: "Bilateral appeal-reconciliation challenge boards are actively supervised with timed quorum restoration, response escalation, and fail-closed contract suspension when cross-organization board review stalls.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_directive_extension_appeal_reconciliation_challenge_automation_actions_total": fmt.Sprintf("%d", len(federationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationRecordIDs)),
				"federation_incident_directive_extension_appeal_reconciliation_challenges_total":                   fmt.Sprintf("%d", len(challenges)),
				"federation_incident_directive_extension_appeal_reconciliation_challenges_pending":                 fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusCount(challenges, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecordIDs) > 0 {
		challengeAppeals := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealsFromRun(run)
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-24",
			ControlName: "Appeal Reconciliation Challenge Appeal Governance",
			Description: "Ruled bilateral appeal-reconciliation challenge boards can be appealed, ruled, and reciprocally acknowledged so final challenge-board enforcement stays governed across organizations.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_actions_total":             fmt.Sprintf("%d", len(federationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecordIDs)),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeals_total":                    fmt.Sprintf("%d", len(challengeAppeals)),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeals_pending":                  fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusCount(challengeAppeals, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview)),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeals_ratified":                 fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusCount(challengeAppeals, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusRatified)),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeals_overturned":               fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusCount(challengeAppeals, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusOverturned)),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeals_enforcement_acknowledged": fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusCount(challengeAppeals, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusEnforcementAcknowledged)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(federationIncidentReportReconciliationRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-FED-08",
			ControlName: "Governed Bilateral Report Reconciliation",
			Description: "Imported counterparty incident reports are not merely observed; bilateral filing alignment is explicitly acknowledged, disputed, and resolved as evidence-bearing cross-organization governance.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append([]string(nil), federationIncidentReportReconciliationRecordIDs...),
			},
			Metadata: map[string]string{
				"federation_incident_report_reconciliation_actions_total":      fmt.Sprintf("%d", len(federationIncidentReportReconciliationRecordIDs)),
				"federation_incident_report_reconciliations_total":             fmt.Sprintf("%d", len(secureCellFederationIncidentReportReconciliationsFromRun(run))),
				"federation_incident_report_reconciliations_aligned":           fmt.Sprintf("%d", secureCellFederationIncidentReportReconciliationStatusCount(secureCellFederationIncidentReportReconciliationsFromRun(run), SecureCellFederationIncidentReportReconciliationStatusAligned)),
				"federation_incident_report_reconciliations_divergent":         fmt.Sprintf("%d", secureCellFederationIncidentReportReconciliationDivergentCount(secureCellFederationIncidentReportReconciliationsFromRun(run))),
				"federation_incident_report_reconciliations_counterparty_only": fmt.Sprintf("%d", secureCellFederationIncidentReportReconciliationStatusCount(secureCellFederationIncidentReportReconciliationsFromRun(run), SecureCellFederationIncidentReportReconciliationStatusCounterpartyOnly)),
			},
		}); err != nil {
			return nil, err
		}
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
			RecordIDs:      recordIDs,
			AttestationIDs: executionAttestationIDs,
			SealIDs:        sealIDs,
			TraceLinkIDs:   traceLinkIDs,
		},
		Metadata: map[string]string{
			"data_classes":                 strings.Join(req.Policy.DataClasses, ","),
			"compute_zones":                strings.Join(req.Policy.ComputeZones, ","),
			"confidential_execution_valid": fmt.Sprintf("%d", len(executionAttestationIDs)),
		},
	}); err != nil {
		return nil, err
	}
	if len(executionAttestationIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-TEE-01",
			ControlName: "Bound Confidential Execution Attestation",
			Description: "Each sealed secure-cell mutation carries verifier-checked TEE attestations bound to the exact workflow stage and output hash.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				AttestationIDs: executionAttestationIDs,
				SealIDs:        sealIDs,
				TraceLinkIDs:   traceLinkIDs,
			},
			Metadata: map[string]string{
				"attestation_count": fmt.Sprintf("%d", len(executionAttestationIDs)),
			},
		}); err != nil {
			return nil, err
		}
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
	if len(sessionEvidenceRecordIDs) > 0 || len(sessionLifecycleRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-SESS-01",
			ControlName: "Governed Collaboration Sessions",
			Description: "Secure-cell sessions are explicitly opened and closed under policy receipts with named participant scope.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append(append([]string(nil), sessionEvidenceRecordIDs...), sessionLifecycleRecordIDs...),
			},
			Metadata: map[string]string{
				"sessions_total":  fmt.Sprintf("%d", len(run.result.Sessions)),
				"sessions_active": fmt.Sprintf("%d", len(sessionsByStatus(run.result.Sessions, SecureCellSessionStatusActive))),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(threadEvidenceRecordIDs) > 0 || len(threadLifecycleRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-THREAD-01",
			ControlName: "Governed Collaboration Threads",
			Description: "Secure-cell sessions can open, contain, resume, and close named collaboration threads under policy-bound lifecycle evidence.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append(append([]string(nil), threadEvidenceRecordIDs...), threadLifecycleRecordIDs...),
			},
			Metadata: map[string]string{
				"threads_total":       fmt.Sprintf("%d", len(run.result.Threads)),
				"threads_active":      fmt.Sprintf("%d", len(threadsByStatus(run.result.Threads, SecureCellThreadStatusActive))),
				"threads_quarantined": fmt.Sprintf("%d", len(threadsByStatus(run.result.Threads, SecureCellThreadStatusQuarantined))),
				"threads_closed":      fmt.Sprintf("%d", len(threadsByStatus(run.result.Threads, SecureCellThreadStatusClosed))),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(decisionEvidenceRecordIDs) > 0 || len(decisionLifecycleRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-DECIDE-01",
			ControlName: "Governed Thread Decisions",
			Description: "Thread-level decisions are created, approved, contained, resumed, and closed under explicit policy-bound lifecycle evidence.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: append(append([]string(nil), decisionEvidenceRecordIDs...), decisionLifecycleRecordIDs...),
			},
			Metadata: map[string]string{
				"decisions_total":            fmt.Sprintf("%d", len(run.result.Decisions)),
				"decisions_open":             fmt.Sprintf("%d", len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusOpen))),
				"decisions_approved":         fmt.Sprintf("%d", len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusApproved))),
				"decisions_quorum_failed":    fmt.Sprintf("%d", len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusQuorumFailed))),
				"decisions_quarantined":      fmt.Sprintf("%d", len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusQuarantined))),
				"decisions_closed":           fmt.Sprintf("%d", len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusClosed))),
				"decision_votes_total":       fmt.Sprintf("%d", secureCellDecisionVoteTotal(run.result.Decisions)),
				"decision_comments_total":    fmt.Sprintf("%d", secureCellDecisionCommentTotal(run.result.Decisions)),
				"decision_delegations_total": fmt.Sprintf("%d", secureCellDecisionDelegationTotal(run.result.Decisions)),
				"decision_outcomes_total":    fmt.Sprintf("%d", len(run.result.DecisionOutcomes)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(decisionVoteRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-DECIDE-VOTE-01",
			ControlName: "Thresholded Decision Approval Votes",
			Description: "Decision approvals are accumulated as explicit, actor-bound votes until the configured threshold is satisfied.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: decisionVoteRecordIDs,
			},
			Metadata: map[string]string{
				"decision_votes_total": fmt.Sprintf("%d", len(decisionVoteRecordIDs)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(decisionCommentRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-DECIDE-COMMENT-01",
			ControlName: "Evidence-Bearing Decision Commentary",
			Description: "Decision comments are preserved as policy-bound collaboration evidence with named actors and chain integrity.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: decisionCommentRecordIDs,
			},
			Metadata: map[string]string{
				"decision_comments_total": fmt.Sprintf("%d", len(decisionCommentRecordIDs)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(decisionDelegationRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-DECIDE-ROUTE-01",
			ControlName: "Decision Delegation And Escalation",
			Description: "Decision flows can delegate or escalate participation without reopening the entire collaboration thread.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: decisionDelegationRecordIDs,
			},
			Metadata: map[string]string{
				"decision_delegations_total": fmt.Sprintf("%d", len(decisionDelegationRecordIDs)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(decisionArtifactContainmentRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-DECIDE-CONT-01",
			ControlName: "Decision-Scoped Output Containment",
			Description: "Decision-linked outputs and exchanges can be contained and released independently from the rest of the collaboration thread.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: decisionArtifactContainmentRecordIDs,
			},
			Metadata: map[string]string{
				"contained_shared_outputs_total":    fmt.Sprintf("%d", secureCellContainedSharedOutputTotal(run.result.SharedOutputs)),
				"contained_session_exchanges_total": fmt.Sprintf("%d", secureCellContainedSessionExchangeTotal(run.result.SessionExchanges)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(decisionOutcomeRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-DECIDE-OUTCOME-01",
			ControlName: "Portable Decision Outcomes",
			Description: "Approved decisions can emit portable outcome bundles linked to the exact outputs and exchanges that informed or resulted from the decision.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs: decisionOutcomeRecordIDs,
			},
			Metadata: map[string]string{
				"decision_outcomes_total": fmt.Sprintf("%d", len(decisionOutcomeRecordIDs)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(sessionExchangeRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-MSG-01",
			ControlName: "Session Exchange Provenance",
			Description: "Session-level exchanges are captured as policy-bound artifacts with integrity hashes, custody history, and verifiable execution evidence.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs:        sessionExchangeRecordIDs,
				PolicyReceiptIDs: sessionExchangePolicyReceiptIDs,
				SealIDs:          sessionExchangeSealIDs,
				TraceLinkIDs:     sessionExchangeTraceLinkIDs,
			},
			Metadata: map[string]string{
				"session_exchanges_total": fmt.Sprintf("%d", len(run.result.SessionExchanges)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(threadMessageRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-THREAD-MSG-01",
			ControlName: "Thread-Scoped Exchange Provenance",
			Description: "Thread-level exchanges are captured as independently containable, policy-bound artifacts with integrity hashes, custody history, and traceable execution evidence.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs:        threadMessageRecordIDs,
				PolicyReceiptIDs: threadMessagePolicyReceiptIDs,
				SealIDs:          threadMessageSealIDs,
				TraceLinkIDs:     threadMessageTraceLinkIDs,
			},
			Metadata: map[string]string{
				"thread_messages_total": fmt.Sprintf("%d", len(threadMessageRecordIDs)),
			},
		}); err != nil {
			return nil, err
		}
	}
	if len(sharedOutputRecordIDs) > 0 {
		if err := ledger.AddControl(evidence.LedgerControl{
			ControlID:   "CELL-SHARE-01",
			ControlName: "Provenance-Bearing Shared Outputs",
			Description: "Session-level shared outputs are recorded with integrity hashes, custody metadata, and policy-bound execution evidence.",
			Status:      evidence.ControlSatisfied,
			EvidenceRefs: evidence.ControlEvidenceRefs{
				RecordIDs:        sharedOutputRecordIDs,
				PolicyReceiptIDs: sharedOutputPolicyReceiptIDs,
				SealIDs:          sharedOutputSealIDs,
				TraceLinkIDs:     sharedOutputTraceLinkIDs,
			},
			Metadata: map[string]string{
				"shared_outputs_total": fmt.Sprintf("%d", len(run.result.SharedOutputs)),
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

func (s *Service) buildConfidentialExecutionRequest(req SecureCellRequest, receiptChain *policy.PolicyReceiptChain, latestReceipt *policy.SignedPolicyReceipt, sealReq sdk.SealRequest, stage string) confidential.AttestationRequest {
	return confidential.AttestationRequest{
		JobID:             cellID(req),
		Workflow:          "secure_cell",
		Stage:             stage,
		Purpose:           req.Purpose,
		Resource:          req.Resource,
		Jurisdiction:      req.Jurisdiction,
		InputHash:         append([]byte(nil), sealReq.InputHash...),
		OutputHash:        append([]byte(nil), sealReq.OutputHash...),
		PolicyReceiptID:   safeString(latestReceipt, func(in *policy.SignedPolicyReceipt) string { return in.ID }),
		PolicyReceiptHash: safeString(latestReceipt, func(in *policy.SignedPolicyReceipt) string { return in.ContentHash }),
		ReceiptChainHash:  safeChainHash(receiptChain),
		Metadata: map[string]string{
			"workflow":                      "secure_cell",
			"cell_id":                       cellID(req),
			"purpose":                       req.Purpose,
			"resource":                      req.Resource,
			"jurisdiction":                  req.Jurisdiction,
			"confidential_compute_required": fmt.Sprintf("%t", confidentialComputeRequired(req.Policy)),
			"cell_stage":                    stage,
		},
	}
}

func (s *Service) confidentialPolicyForRequest(req SecureCellRequest) confidential.Policy {
	policy := s.config.ConfidentialPolicy
	policy.Required = policy.Required || confidentialComputeRequired(req.Policy)
	return policy
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

func (s *Service) evaluateStage(ctx context.Context, req SecureCellRequest, stage string, previousReceiptHash string, extraMetadata map[string]string, actorDID string) (*policy.SignedPolicyReceipt, error) {
	actorDID = firstNonEmpty(strings.TrimSpace(actorDID), req.OwnerIdentity.AgentID())
	evalReq := &policy.EvaluationRequest{
		Actor:    actorDID,
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

func (s *Service) buildLifecycleEvent(run *secureCellRun, transition SecureCellTransition) SecureCellLifecycleEvent {
	event := SecureCellLifecycleEvent{
		EventID:                     firstNonEmpty(strings.TrimSpace(transition.ID), fmt.Sprintf("%s-event", run.result.CellID)),
		CellID:                      run.result.CellID,
		Name:                        run.result.Name,
		Purpose:                     run.result.Purpose,
		Jurisdiction:                run.request.Jurisdiction,
		Action:                      transition.Action,
		Actor:                       transition.Actor,
		TargetType:                  transition.TargetType,
		TargetDID:                   transition.TargetDID,
		SessionID:                   transition.SessionID,
		ThreadID:                    transition.ThreadID,
		DecisionID:                  transition.DecisionID,
		SharedOutputID:              transition.SharedOutputID,
		SessionExchangeID:           transition.SessionExchangeID,
		SessionStatusBefore:         transition.SessionStatusBefore,
		SessionStatusAfter:          transition.SessionStatusAfter,
		ThreadStatusBefore:          transition.ThreadStatusBefore,
		ThreadStatusAfter:           transition.ThreadStatusAfter,
		DecisionStatusBefore:        transition.DecisionStatusBefore,
		DecisionStatusAfter:         transition.DecisionStatusAfter,
		CellStatus:                  run.result.Status,
		CellStatusBefore:            transition.CellStatusBefore,
		CellStatusAfter:             transition.CellStatusAfter,
		ParticipantStatusBefore:     transition.ParticipantStatusBefore,
		ParticipantStatusAfter:      transition.ParticipantStatusAfter,
		TransitionID:                transition.ID,
		TransitionCount:             len(run.result.Transitions),
		ParticipantCount:            len(run.result.Participants),
		SessionCount:                len(run.result.Sessions),
		ActiveSessionCount:          len(sessionsByStatus(run.result.Sessions, SecureCellSessionStatusActive)),
		ThreadCount:                 len(run.result.Threads),
		ActiveThreadCount:           len(threadsByStatus(run.result.Threads, SecureCellThreadStatusActive)),
		DecisionCount:               len(run.result.Decisions),
		OpenDecisionCount:           len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusOpen)),
		ApprovedDecisionCount:       len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusApproved)),
		QuorumFailedDecisionCount:   len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusQuorumFailed)),
		QuarantinedDecisionCount:    len(decisionsByStatus(run.result.Decisions, SecureCellThreadDecisionStatusQuarantined)),
		SharedOutputCount:           len(run.result.SharedOutputs),
		SessionExchangeCount:        len(run.result.SessionExchanges),
		ActiveParticipantCount:      len(participantsByStatus(run.result.Participants, SecureCellParticipantStatusActive)),
		QuarantinedParticipantCount: len(participantsByStatus(run.result.Participants, SecureCellParticipantStatusQuarantined)),
		RevokedParticipantCount:     len(participantsByStatus(run.result.Participants, SecureCellParticipantStatusRevoked)),
		Reason:                      strings.TrimSpace(transition.Reason),
		Metadata:                    cloneStringMap(transition.Metadata),
		OccurredAt:                  transition.OccurredAt.UTC(),
		PublishedAt:                 time.Now().UTC(),
	}
	if transition.PolicyReceipt != nil {
		event.PolicyReceiptID = transition.PolicyReceipt.ID
		event.PolicyReceiptContentHash = transition.PolicyReceipt.ContentHash
	}
	if run.result.ReceiptChain != nil {
		event.ReceiptChainHash = run.result.ReceiptChain.ChainHash
	}
	if run.result.ExecutionSeal != nil {
		event.SealID = run.result.ExecutionSeal.SealID
	}
	if run.result.ControlLedger != nil && run.result.ControlLedger.Bundle != nil {
		event.ControlLedgerID = run.result.ControlLedger.Bundle.ID
		event.ControlLedgerContentHash = run.result.ControlLedger.Bundle.ContentHash
	}
	if run.result.PortablePackage != nil {
		event.PortablePackageHash = run.result.PortablePackage.PackageHash
		event.PortablePackageSigned = run.result.PortablePackage.Signature != nil
		event.PortablePackageAnchored = run.result.PortablePackage.AuditAnchor != nil
	}
	return event
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

func (s *Service) loadPersistedRuns(ctx context.Context) error {
	if s == nil || s.config.WorkflowStore == nil {
		return nil
	}
	records, err := s.config.WorkflowStore.List(ctx)
	if err != nil {
		return err
	}
	for _, record := range records {
		run, err := s.runFromRecord(record)
		if err != nil {
			return err
		}
		s.setRun(run)
	}
	return nil
}

func (s *Service) runFromRecord(record *SecureCellRecord) (*secureCellRun, error) {
	cloned, _, err := prepareSecureCellRecordForStorage(record)
	if err != nil {
		return nil, err
	}
	return &secureCellRun{
		request: cloned.Request,
		result:  cloned.Result,
	}, nil
}

func (s *Service) persistRun(ctx context.Context, run *secureCellRun) error {
	if s == nil || s.config.WorkflowStore == nil || run == nil || run.result == nil {
		return nil
	}
	record := &SecureCellRecord{
		CellID:   run.result.CellID,
		Request:  run.request,
		Result:   run.result,
		StoredAt: time.Now().UTC(),
	}
	if err := s.config.WorkflowStore.Save(ctx, record); err != nil {
		return fmt.Errorf("securecells/service: persist workflow state: %w", err)
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

func (s *Service) runCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.runs)
}

func (s *Service) setRun(run *secureCellRun) {
	if run == nil || run.result == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[run.result.CellID] = run
}

func (s *Service) bulkTransitionMembers(
	ctx context.Context,
	cellID string,
	action string,
	bulk SecureCellBulkMemberTransitionRequest,
	fn func(context.Context, string, SecureCellMemberTransitionRequest) (*SecureCellResult, error),
) (*SecureCellBulkMemberTransitionResult, error) {
	participantDIDs := uniqueTrimmedStrings(bulk.ParticipantDIDs)
	if len(participantDIDs) == 0 {
		return nil, fmt.Errorf("securecells/service: at least one participant DID is required")
	}
	result := &SecureCellBulkMemberTransitionResult{
		CellID:         strings.TrimSpace(cellID),
		Action:         action,
		RequestedCount: len(participantDIDs),
		Results:        make([]SecureCellBulkMemberTransitionItem, 0, len(participantDIDs)),
	}
	for _, participantDID := range participantDIDs {
		run, err := fn(ctx, cellID, SecureCellMemberTransitionRequest{
			ParticipantDID:      participantDID,
			ActorDID:            bulk.ActorDID,
			Reason:              bulk.Reason,
			QuarantineExpiresAt: bulk.QuarantineExpiresAt,
			Metadata:            bulk.Metadata,
		})
		item := SecureCellBulkMemberTransitionItem{
			ParticipantDID: participantDID,
		}
		if err != nil {
			item.Result = "failed"
			item.Error = err.Error()
			result.FailedCount++
		} else {
			item.Result = "applied"
			if state, ok := participantStateForResult(run, participantDID); ok {
				item.Status = state.Status
			}
			result.SucceededCount++
			result.FinalState = run
		}
		result.Results = append(result.Results, item)
	}
	if result.FinalState == nil {
		run, err := s.GetCell(ctx, cellID)
		if err != nil {
			return result, nil
		}
		result.FinalState = run
	}
	return result, nil
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

func secureCellHasParticipant(states []SecureCellParticipantState, did string) bool {
	_, participant := findParticipantState(states, did)
	return participant != nil
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

func secureCellSummaryFromRun(run *secureCellRun) SecureCellSummary {
	if run == nil || run.result == nil {
		return SecureCellSummary{}
	}
	active := len(participantsByStatus(run.result.Participants, SecureCellParticipantStatusActive))
	quarantined := len(participantsByStatus(run.result.Participants, SecureCellParticipantStatusQuarantined))
	revoked := len(participantsByStatus(run.result.Participants, SecureCellParticipantStatusRevoked))
	return SecureCellSummary{
		CellID:                      run.result.CellID,
		Name:                        run.result.Name,
		Purpose:                     run.result.Purpose,
		Jurisdiction:                run.request.Jurisdiction,
		Status:                      run.result.Status,
		PausedFromStatus:            run.result.PausedFromStatus,
		ParticipantCount:            len(run.result.Participants),
		ActiveParticipantCount:      active,
		QuarantinedParticipantCount: quarantined,
		RevokedParticipantCount:     revoked,
		TransitionCount:             len(run.result.Transitions),
		HasControlLedger:            run.result.ControlLedger != nil,
		HasPortablePackage:          run.result.PortablePackage != nil,
		NextQuarantineExpiry:        nextQuarantineExpiry(run.result.Participants),
		TerminatedAt:                cloneTimePtr(run.result.TerminatedAt),
		CreatedAt:                   run.result.CreatedAt.UTC(),
		UpdatedAt:                   run.result.UpdatedAt.UTC(),
	}
}

func nextQuarantineExpiry(states []SecureCellParticipantState) *time.Time {
	var next *time.Time
	for _, state := range states {
		if state.Status != SecureCellParticipantStatusQuarantined || state.QuarantineExpiresAt == nil {
			continue
		}
		expiresAt := state.QuarantineExpiresAt.UTC()
		if next == nil || expiresAt.Before(*next) {
			next = &expiresAt
		}
	}
	return next
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
	case "secure_cell.member_admitted", "secure_cell.federation_invited", "secure_cell.federation_joined", "secure_cell.federation_invitation_revoked", "secure_cell.federation_counterproposed", "secure_cell.federation_counterproposal_vote_recorded", "secure_cell.federation_counterproposal_escalated", "secure_cell.federation_counterproposal_approved", "secure_cell.federation_counterproposal_rejected", "secure_cell.federation_contract_revoked", "secure_cell.federation_contract_renewed", "secure_cell.federation_contract_suspended", "secure_cell.federation_contract_resumed", "secure_cell.federation_assurance_ingested", "secure_cell.federation_incident_published", "secure_cell.federation_incident_resolved", "secure_cell.federation_incident_bulletin_ingested", "secure_cell.federation_incident_report_amendment_bundle_ingested", "secure_cell.federation_incident_directive_extension_appeal_bundle_ingested", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_acknowledged", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_disputed", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_resolved", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenged", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_review_delegated", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_vote_recorded", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_ruled", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_dispute_acknowledged", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_correction_attested", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_resolution_attested", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_escalated", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appealed", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_vote_recorded", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruled", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_acknowledged", "secure_cell.federation_incident_response_acknowledged", "secure_cell.federation_incident_response_escalated", "secure_cell.federation_incident_response_remediation_attested", "secure_cell.federation_incident_remediation_verified", "secure_cell.federation_incident_directive_issued", "secure_cell.federation_incident_directive_acknowledged", "secure_cell.federation_incident_directive_completed", "secure_cell.federation_incident_directive_verified", "secure_cell.federation_incident_report_planned", "secure_cell.federation_incident_report_amendment_created", "secure_cell.federation_incident_report_submitted", "secure_cell.federation_incident_report_acknowledged", "secure_cell.federation_incident_report_amendment_submitted", "secure_cell.federation_incident_report_amendment_acknowledged", "secure_cell.federation_incident_report_amendment_reconciliation_acknowledged", "secure_cell.federation_incident_report_amendment_reconciliation_disputed", "secure_cell.federation_incident_report_amendment_reconciliation_resolved", "secure_cell.federation_incident_report_amendment_reconciliation_dispute_acknowledged", "secure_cell.federation_incident_report_amendment_reconciliation_correction_attested", "secure_cell.federation_incident_report_amendment_reconciliation_resolution_attested", "secure_cell.federation_incident_report_amendment_reconciliation_escalated":
		return "trust"
	case "secure_cell.session_started", "secure_cell.session_closed", "secure_cell.session_paused", "secure_cell.session_resumed", "secure_cell.session_member_admitted", "secure_cell.session_member_removed", "secure_cell.session_thread_started", "secure_cell.session_thread_closed", "secure_cell.session_thread_resumed", "secure_cell.session_thread_decision_created", "secure_cell.session_thread_decision_voted", "secure_cell.session_thread_decision_approved", "secure_cell.session_thread_decision_quorum_failed", "secure_cell.session_thread_decision_commented", "secure_cell.session_thread_decision_delegated", "secure_cell.session_thread_decision_escalated", "secure_cell.session_thread_decision_resumed", "secure_cell.session_thread_decision_closed":
		return "collaboration"
	case "secure_cell.session_shared", "secure_cell.session_exchange", "secure_cell.session_thread_message", "secure_cell.session_thread_decision_outcome_published":
		return "exchange"
	case "secure_cell.member_quarantined", "secure_cell.member_revoked", "secure_cell.member_released", "secure_cell.quarantine_expired", "secure_cell.session_quarantined", "secure_cell.session_thread_quarantined", "secure_cell.session_thread_decision_quarantined", "secure_cell.session_thread_decision_outputs_contained", "secure_cell.session_thread_decision_outputs_released", "secure_cell.federation_incident_artifacts_contained":
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
	case "secure_cell.federation_invited":
		return "invite_federation_member"
	case "secure_cell.federation_joined":
		return "accept_federation_invitation"
	case "secure_cell.federation_invitation_revoked":
		return "revoke_federation_invitation"
	case "secure_cell.federation_counterproposed":
		return "counterpropose_federation_invitation"
	case "secure_cell.federation_counterproposal_vote_recorded":
		return "approve_federation_counterproposal"
	case "secure_cell.federation_counterproposal_escalated":
		return "escalate_federation_counterproposal"
	case "secure_cell.federation_counterproposal_approved":
		return "approve_federation_counterproposal"
	case "secure_cell.federation_counterproposal_rejected":
		return "reject_federation_counterproposal"
	case "secure_cell.federation_contract_revoked":
		return "revoke_federation_contract"
	case "secure_cell.federation_contract_renewed":
		return "renew_federation_contract"
	case "secure_cell.federation_contract_suspended":
		return "suspend_federation_contract"
	case "secure_cell.federation_contract_resumed":
		return "resume_federation_contract"
	case "secure_cell.federation_assurance_ingested":
		return "intake_federation_assurance"
	case "secure_cell.federation_incident_published":
		return "publish_federation_incident"
	case "secure_cell.federation_incident_resolved":
		return "resolve_federation_incident"
	case "secure_cell.federation_incident_bulletin_ingested":
		return "intake_federation_incident_bulletin"
	case "secure_cell.federation_incident_artifacts_contained":
		return "contain_federation_incident_artifacts"
	case "secure_cell.federation_incident_response_acknowledged":
		return "acknowledge_federation_incident_response"
	case "secure_cell.federation_incident_response_escalated":
		return "escalate_federation_incident_response"
	case "secure_cell.federation_incident_response_remediation_attested":
		return "attest_federation_incident_remediation"
	case "secure_cell.federation_incident_remediation_verified":
		return "verify_federation_incident_remediation"
	case "secure_cell.federation_incident_closure_attested":
		return "attest_federation_incident_closure"
	case "secure_cell.federation_incident_response_disputed":
		return "dispute_federation_incident_response"
	case "secure_cell.federation_incident_directive_issued":
		return "issue_federation_incident_directive"
	case "secure_cell.federation_incident_directive_acknowledged":
		return "acknowledge_federation_incident_directive"
	case "secure_cell.federation_incident_directive_completed":
		return "complete_federation_incident_directive"
	case "secure_cell.federation_incident_directive_verified":
		return "verify_federation_incident_directive"
	case "secure_cell.federation_incident_directive_extension_requested":
		return "request_federation_incident_directive_extension"
	case "secure_cell.federation_incident_directive_extension_approved":
		return "approve_federation_incident_directive_extension"
	case "secure_cell.federation_incident_directive_extension_rejected":
		return "reject_federation_incident_directive_extension"
	case "secure_cell.federation_incident_directive_extension_disputed":
		return "dispute_federation_incident_directive_extension"
	case "secure_cell.federation_incident_directive_extension_dispute_resolved":
		return "resolve_federation_incident_directive_extension_dispute"
	case "secure_cell.federation_incident_directive_extension_review_delegated":
		return "delegate_federation_incident_directive_extension_review"
	case "secure_cell.federation_incident_directive_extension_dispute_resolution_delegated":
		return "delegate_federation_incident_directive_extension_dispute_resolution"
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_acknowledged":
		return "acknowledge_federation_incident_directive_extension_appeal_reconciliation"
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_disputed":
		return "dispute_federation_incident_directive_extension_appeal_reconciliation"
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_resolved":
		return "resolve_federation_incident_directive_extension_appeal_reconciliation"
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenged":
		return "challenge_federation_incident_directive_extension_appeal_reconciliation"
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_review_delegated":
		return "delegate_federation_incident_directive_extension_appeal_reconciliation_review"
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_vote_recorded", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_ruled":
		return "rule_federation_incident_directive_extension_appeal_reconciliation"
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appealed":
		return "appeal_federation_incident_directive_extension_appeal_reconciliation_challenge"
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_vote_recorded", "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruled":
		return "rule_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal"
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_acknowledged":
		return "acknowledge_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement"
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_dispute_acknowledged":
		return "acknowledge_federation_incident_directive_extension_appeal_reconciliation_dispute"
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_correction_attested":
		return "attest_federation_incident_directive_extension_appeal_reconciliation_correction"
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_resolution_attested":
		return "attest_federation_incident_directive_extension_appeal_reconciliation_resolution"
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_escalated":
		return "escalate_federation_incident_directive_extension_appeal_reconciliation"
	case "secure_cell.federation_incident_report_planned":
		return "plan_federation_incident_report"
	case "secure_cell.federation_incident_report_amendment_created":
		return "amend_federation_incident_report"
	case "secure_cell.federation_incident_report_submitted":
		return "submit_federation_incident_report"
	case "secure_cell.federation_incident_report_acknowledged":
		return "acknowledge_federation_incident_report"
	case "secure_cell.federation_incident_report_amendment_bundle_ingested":
		return "intake_federation_incident_report_amendment_bundle"
	case "secure_cell.federation_incident_directive_extension_appeal_bundle_ingested":
		return "intake_federation_incident_directive_extension_appeal_bundle"
	case "secure_cell.federation_incident_report_amendment_submitted":
		return "submit_federation_incident_report_amendment"
	case "secure_cell.federation_incident_report_amendment_acknowledged":
		return "acknowledge_federation_incident_report_amendment"
	case "secure_cell.federation_incident_report_amendment_reconciliation_acknowledged":
		return "acknowledge_federation_incident_report_amendment_reconciliation"
	case "secure_cell.federation_incident_report_amendment_reconciliation_disputed":
		return "dispute_federation_incident_report_amendment_reconciliation"
	case "secure_cell.federation_incident_report_amendment_reconciliation_resolved":
		return "resolve_federation_incident_report_amendment_reconciliation"
	case "secure_cell.federation_incident_report_amendment_reconciliation_dispute_acknowledged":
		return "acknowledge_federation_incident_report_amendment_reconciliation_dispute"
	case "secure_cell.federation_incident_report_amendment_reconciliation_correction_attested":
		return "attest_federation_incident_report_amendment_reconciliation_correction"
	case "secure_cell.federation_incident_report_amendment_reconciliation_resolution_attested":
		return "attest_federation_incident_report_amendment_reconciliation_resolution"
	case "secure_cell.federation_incident_report_amendment_reconciliation_escalated":
		return "escalate_federation_incident_report_amendment_reconciliation"
	case "secure_cell.session_started":
		return "start_session"
	case "secure_cell.session_thread_started":
		return "start_session_thread"
	case "secure_cell.session_thread_message":
		return "message_session_thread"
	case "secure_cell.session_thread_decision_created":
		return "create_thread_decision"
	case "secure_cell.session_thread_decision_voted":
		return "approve_thread_decision"
	case "secure_cell.session_thread_decision_approved":
		return "approve_thread_decision"
	case "secure_cell.session_thread_decision_quorum_failed":
		return "approve_thread_decision"
	case "secure_cell.session_thread_decision_commented":
		return "comment_thread_decision"
	case "secure_cell.session_thread_decision_delegated":
		return "delegate_thread_decision"
	case "secure_cell.session_thread_decision_escalated":
		return "escalate_thread_decision"
	case "secure_cell.session_thread_decision_outcome_published":
		return "publish_thread_decision_outcome"
	case "secure_cell.session_thread_decision_resumed":
		return "resume_thread_decision"
	case "secure_cell.session_thread_decision_quarantined":
		return "quarantine_thread_decision"
	case "secure_cell.session_thread_decision_outputs_contained":
		return "contain_thread_decision_outputs"
	case "secure_cell.session_thread_decision_outputs_released":
		return "release_thread_decision_outputs"
	case "secure_cell.session_thread_decision_closed":
		return "close_thread_decision"
	case "secure_cell.session_exchange":
		return "exchange_session_message"
	case "secure_cell.session_shared":
		return "share_session_output"
	case "secure_cell.session_closed":
		return "close_session"
	case "secure_cell.session_paused":
		return "pause_session"
	case "secure_cell.session_resumed":
		return "resume_session"
	case "secure_cell.session_quarantined":
		return "quarantine_session"
	case "secure_cell.session_thread_closed":
		return "close_session_thread"
	case "secure_cell.session_thread_resumed":
		return "resume_session_thread"
	case "secure_cell.session_thread_quarantined":
		return "quarantine_session_thread"
	case "secure_cell.session_member_admitted":
		return "admit_session_member"
	case "secure_cell.session_member_removed":
		return "remove_session_member"
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

func sessionStatusAllowed(current SecureCellSessionStatus, allowed ...SecureCellSessionStatus) bool {
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

func threadStatusAllowed(current SecureCellThreadStatus, allowed ...SecureCellThreadStatus) bool {
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

func decisionStatusAllowed(current SecureCellThreadDecisionStatus, allowed ...SecureCellThreadDecisionStatus) bool {
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

func participantStateForResult(result *SecureCellResult, participantDID string) (SecureCellParticipantState, bool) {
	if result == nil {
		return SecureCellParticipantState{}, false
	}
	for _, participant := range result.Participants {
		if strings.TrimSpace(participant.ParticipantDID) == strings.TrimSpace(participantDID) {
			return participant, true
		}
	}
	return SecureCellParticipantState{}, false
}

func findSecureCellSession(sessions []SecureCellSession, sessionID string) (int, *SecureCellSession) {
	sessionID = strings.TrimSpace(sessionID)
	for idx := range sessions {
		if strings.TrimSpace(sessions[idx].ID) == sessionID {
			return idx, &sessions[idx]
		}
	}
	return -1, nil
}

func findSecureCellThread(threads []SecureCellSessionThread, threadID string) (int, *SecureCellSessionThread) {
	threadID = strings.TrimSpace(threadID)
	for idx := range threads {
		if strings.TrimSpace(threads[idx].ID) == threadID {
			return idx, &threads[idx]
		}
	}
	return -1, nil
}

func findSecureCellThreadDecision(decisions []SecureCellThreadDecision, decisionID string) (int, *SecureCellThreadDecision) {
	decisionID = strings.TrimSpace(decisionID)
	for idx := range decisions {
		if strings.TrimSpace(decisions[idx].ID) == decisionID {
			return idx, &decisions[idx]
		}
	}
	return -1, nil
}

func findSecureCellSharedOutputIndex(outputs []SecureCellSharedOutput, outputID string) int {
	outputID = strings.TrimSpace(outputID)
	for idx := range outputs {
		if strings.TrimSpace(outputs[idx].ID) == outputID {
			return idx
		}
	}
	return -1
}

func findSecureCellSessionExchangeIndex(exchanges []SecureCellSessionExchange, exchangeID string) int {
	exchangeID = strings.TrimSpace(exchangeID)
	for idx := range exchanges {
		if strings.TrimSpace(exchanges[idx].ID) == exchangeID {
			return idx
		}
	}
	return -1
}

func decisionApprovalThreshold(decision SecureCellThreadDecision) int {
	return normalizeSecureCellThreshold(decision.ApprovalThreshold)
}

func secureCellDecisionApproverAllowed(run *secureCellRun, thread SecureCellSessionThread, decision SecureCellThreadDecision, actorDID string) bool {
	actorDID = strings.TrimSpace(actorDID)
	if actorDID == "" {
		return false
	}
	if !secureCellDecisionActorAllowed(run, thread, decision, actorDID) {
		return false
	}
	eligible := uniqueTrimmedStrings(decision.EligibleApproverDIDs)
	requiredRoles := uniqueSecureCellDecisionRoles(decision.RequiredApproverRoles)
	actorRole := secureCellActorRole(run, actorDID)
	if len(eligible) == 0 && len(requiredRoles) == 0 {
		return true
	}
	for _, eligibleDID := range eligible {
		if eligibleDID == actorDID {
			return true
		}
	}
	for _, requiredRole := range requiredRoles {
		if requiredRole == actorRole {
			return true
		}
	}
	return false
}

func secureCellDecisionHasApprovalVote(decision SecureCellThreadDecision, actorDID string) bool {
	actorDID = strings.TrimSpace(actorDID)
	for _, vote := range decision.ApprovalVotes {
		if strings.TrimSpace(vote.ActorDID) == actorDID {
			return true
		}
	}
	return false
}

func secureCellDecisionVoteTotal(decisions []SecureCellThreadDecision) int {
	total := 0
	for _, decision := range decisions {
		total += len(decision.ApprovalVotes)
	}
	return total
}

func secureCellDecisionApprovalReachable(run *secureCellRun, thread SecureCellSessionThread, decision SecureCellThreadDecision) bool {
	if secureCellDecisionApprovalSatisfied(decision) {
		return true
	}
	approveVotes := 0
	for _, vote := range decision.ApprovalVotes {
		if vote.Choice == SecureCellThreadDecisionVoteChoiceApprove {
			approveVotes++
		}
	}
	remainingApproves := 0
	remainingRoles := make(map[string]struct{})
	candidateApprovers := map[string]struct{}{}
	if run != nil && run.request.OwnerIdentity != nil {
		candidateApprovers[run.request.OwnerIdentity.AgentID()] = struct{}{}
	}
	for _, actorDID := range thread.ParticipantDIDs {
		if trimmed := strings.TrimSpace(actorDID); trimmed != "" {
			candidateApprovers[trimmed] = struct{}{}
		}
	}
	for _, actorDID := range decision.EligibleApproverDIDs {
		if trimmed := strings.TrimSpace(actorDID); trimmed != "" {
			candidateApprovers[trimmed] = struct{}{}
		}
	}
	for _, delegation := range decision.Delegations {
		if trimmed := strings.TrimSpace(delegation.ToActorDID); trimmed != "" {
			candidateApprovers[trimmed] = struct{}{}
		}
	}
	requiredRoles := uniqueSecureCellDecisionRoles(decision.RequiredApproverRoles)
	if len(requiredRoles) > 0 && run != nil && run.result != nil {
		for _, participant := range run.result.Participants {
			if participant.Status != SecureCellParticipantStatusActive {
				continue
			}
			for _, requiredRole := range requiredRoles {
				if strings.TrimSpace(participant.Role) == requiredRole {
					candidateApprovers[strings.TrimSpace(participant.ParticipantDID)] = struct{}{}
					break
				}
			}
		}
	}
	for actorDID := range candidateApprovers {
		if secureCellDecisionHasApprovalVote(decision, actorDID) {
			continue
		}
		if !secureCellDecisionApproverAllowed(run, thread, decision, actorDID) {
			continue
		}
		remainingApproves++
		if actorRole := secureCellActorRole(run, actorDID); actorRole != "" {
			remainingRoles[actorRole] = struct{}{}
		}
	}
	if approveVotes+remainingApproves < decisionApprovalThreshold(decision) {
		return false
	}
	for _, requiredRole := range secureCellDecisionMissingRequiredRoles(decision) {
		if _, ok := remainingRoles[requiredRole]; !ok {
			return false
		}
	}
	return true
}

func secureCellDecisionVoteChoiceEnabled(decision SecureCellThreadDecision, choice SecureCellThreadDecisionVoteChoice) bool {
	choice = SecureCellThreadDecisionVoteChoice(strings.ToLower(strings.TrimSpace(string(choice))))
	if choice == "" {
		return false
	}
	allowed := normalizeSecureCellDecisionVoteChoices(decision.AllowedVoteChoices)
	if len(allowed) == 0 {
		allowed = []SecureCellThreadDecisionVoteChoice{
			SecureCellThreadDecisionVoteChoiceApprove,
			SecureCellThreadDecisionVoteChoiceReject,
			SecureCellThreadDecisionVoteChoiceAbstain,
		}
	}
	for _, candidate := range allowed {
		if candidate == choice {
			return true
		}
	}
	return false
}

func secureCellDecisionRoleRuleAllows(actorRole string, allowedRoles []string) bool {
	allowedRoles = uniqueSecureCellDecisionRoles(allowedRoles)
	if len(allowedRoles) == 0 {
		return true
	}
	actorRole = strings.TrimSpace(strings.ToLower(actorRole))
	for _, allowedRole := range allowedRoles {
		if allowedRole == actorRole {
			return true
		}
	}
	return false
}

func secureCellDecisionCommentTotal(decisions []SecureCellThreadDecision) int {
	total := 0
	for _, decision := range decisions {
		total += len(decision.Comments)
	}
	return total
}

func secureCellDecisionDelegationTotal(decisions []SecureCellThreadDecision) int {
	total := 0
	for _, decision := range decisions {
		total += len(decision.Delegations)
	}
	return total
}

func secureCellDecisionActorAllowed(run *secureCellRun, thread SecureCellSessionThread, decision SecureCellThreadDecision, actorDID string) bool {
	if secureCellThreadActorAllowed(run, thread, actorDID) {
		return true
	}
	if !secureCellDecisionParticipantAllowed(run, actorDID) {
		return false
	}
	for _, eligibleDID := range decision.EligibleApproverDIDs {
		if strings.TrimSpace(eligibleDID) == strings.TrimSpace(actorDID) {
			return true
		}
	}
	for _, delegation := range decision.Delegations {
		if strings.TrimSpace(delegation.ToActorDID) == strings.TrimSpace(actorDID) {
			return true
		}
	}
	actorRole := secureCellActorRole(run, actorDID)
	for _, requiredRole := range decision.RequiredApproverRoles {
		if strings.TrimSpace(requiredRole) == actorRole {
			return true
		}
	}
	return false
}

func secureCellDecisionParticipantAllowed(run *secureCellRun, actorDID string) bool {
	actorDID = strings.TrimSpace(actorDID)
	if actorDID == "" || run == nil || run.result == nil || run.request.OwnerIdentity == nil {
		return false
	}
	if run.request.OwnerIdentity.AgentID() == actorDID {
		return true
	}
	state, ok := participantStateForResult(run.result, actorDID)
	return ok && state.Status == SecureCellParticipantStatusActive
}

func secureCellActorRole(run *secureCellRun, actorDID string) string {
	actorDID = strings.TrimSpace(actorDID)
	if actorDID == "" || run == nil || run.request.OwnerIdentity == nil {
		return ""
	}
	if run.request.OwnerIdentity.AgentID() == actorDID {
		return "owner"
	}
	if state, ok := participantStateForResult(run.result, actorDID); ok {
		return strings.TrimSpace(state.Role)
	}
	return ""
}

func secureCellDecisionRoleAvailable(run *secureCellRun, thread SecureCellSessionThread, role string) bool {
	role = strings.TrimSpace(strings.ToLower(role))
	if role == "" {
		return false
	}
	if role == "owner" && run != nil && run.request.OwnerIdentity != nil {
		return true
	}
	for _, participantDID := range thread.ParticipantDIDs {
		if strings.EqualFold(secureCellActorRole(run, participantDID), role) {
			return true
		}
	}
	if run != nil && run.result != nil {
		for _, participant := range run.result.Participants {
			if participant.Status == SecureCellParticipantStatusActive && strings.EqualFold(strings.TrimSpace(participant.Role), role) {
				return true
			}
		}
	}
	return false
}

func uniqueSecureCellDecisionRoles(values []string) []string {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(strings.ToLower(value))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func normalizeSecureCellDecisionVoteChoices(values []SecureCellThreadDecisionVoteChoice) []SecureCellThreadDecisionVoteChoice {
	if len(values) == 0 {
		return nil
	}
	out := make([]SecureCellThreadDecisionVoteChoice, 0, len(values))
	seen := make(map[SecureCellThreadDecisionVoteChoice]struct{}, len(values))
	for _, value := range values {
		normalized := SecureCellThreadDecisionVoteChoice(strings.ToLower(strings.TrimSpace(string(value))))
		switch normalized {
		case SecureCellThreadDecisionVoteChoiceApprove, SecureCellThreadDecisionVoteChoiceReject, SecureCellThreadDecisionVoteChoiceAbstain:
		default:
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func resolveSecureCellDecisionGovernance(template string, allowedChoices []SecureCellThreadDecisionVoteChoice, rejectorRoles, abstainerRoles, reopenRoles []string) (string, []SecureCellThreadDecisionVoteChoice, []string, []string, []string, error) {
	template = strings.TrimSpace(strings.ToLower(template))
	defaultChoices := []SecureCellThreadDecisionVoteChoice{
		SecureCellThreadDecisionVoteChoiceApprove,
		SecureCellThreadDecisionVoteChoiceReject,
		SecureCellThreadDecisionVoteChoiceAbstain,
	}
	defaultRejectorRoles := []string(nil)
	defaultAbstainerRoles := []string(nil)
	defaultReopenRoles := []string(nil)

	switch template {
	case "", "standard_review":
		if template == "" {
			template = "standard_review"
		}
	case "dual_control":
		defaultChoices = []SecureCellThreadDecisionVoteChoice{
			SecureCellThreadDecisionVoteChoiceApprove,
			SecureCellThreadDecisionVoteChoiceReject,
		}
		defaultRejectorRoles = []string{"owner"}
		defaultReopenRoles = []string{"owner"}
	case "board_escalation":
		defaultRejectorRoles = []string{"owner", "board_reviewer"}
		defaultAbstainerRoles = []string{"owner", "board_reviewer", "reviewer_b"}
		defaultReopenRoles = []string{"owner", "board_reviewer"}
	default:
		return "", nil, nil, nil, nil, fmt.Errorf("securecells/service: unsupported decision governance template %q", template)
	}

	allowedChoices = normalizeSecureCellDecisionVoteChoices(allowedChoices)
	if len(allowedChoices) == 0 {
		allowedChoices = append([]SecureCellThreadDecisionVoteChoice(nil), defaultChoices...)
	}
	rejectorRoles = firstNonEmptyDecisionRoles(rejectorRoles, defaultRejectorRoles)
	abstainerRoles = firstNonEmptyDecisionRoles(abstainerRoles, defaultAbstainerRoles)
	reopenRoles = firstNonEmptyDecisionRoles(reopenRoles, defaultReopenRoles)
	return template, allowedChoices, rejectorRoles, abstainerRoles, reopenRoles, nil
}

func normalizeSecureCellDecisionEscalationLadder(ladder []SecureCellDecisionEscalationTier, fallbackTarget string, fallbackDueAt *time.Time) ([]SecureCellDecisionEscalationTier, error) {
	normalized := make([]SecureCellDecisionEscalationTier, 0, len(ladder)+1)
	seenTierIDs := make(map[string]struct{}, len(ladder))
	for idx, tier := range ladder {
		targetDID := strings.TrimSpace(tier.TargetDID)
		if targetDID == "" {
			return nil, fmt.Errorf("securecells/service: escalation ladder tier %d target_did is required", idx+1)
		}
		if tier.DueAt == nil || tier.DueAt.IsZero() {
			return nil, fmt.Errorf("securecells/service: escalation ladder tier %d due_at is required", idx+1)
		}
		tierID := strings.TrimSpace(tier.TierID)
		if tierID == "" {
			tierID = fmt.Sprintf("tier_%d", idx+1)
		}
		if _, ok := seenTierIDs[tierID]; ok {
			return nil, fmt.Errorf("securecells/service: duplicate escalation ladder tier_id %q", tierID)
		}
		seenTierIDs[tierID] = struct{}{}
		dueAt := tier.DueAt.UTC()
		mode := tier.Mode
		if mode == "" {
			mode = SecureCellThreadDecisionDelegationModeEscalate
		}
		if mode != SecureCellThreadDecisionDelegationModeEscalate && mode != SecureCellThreadDecisionDelegationModeDelegate {
			return nil, fmt.Errorf("securecells/service: unsupported escalation ladder mode %q", mode)
		}
		normalized = append(normalized, SecureCellDecisionEscalationTier{
			TierID:    tierID,
			TargetDID: targetDID,
			Mode:      mode,
			DueAt:     &dueAt,
			Reason:    strings.TrimSpace(tier.Reason),
			Metadata:  cloneStringMap(tier.Metadata),
		})
	}
	if len(normalized) == 0 && strings.TrimSpace(fallbackTarget) != "" && fallbackDueAt != nil && !fallbackDueAt.IsZero() {
		dueAt := fallbackDueAt.UTC()
		normalized = append(normalized, SecureCellDecisionEscalationTier{
			TierID:    "tier_1",
			TargetDID: strings.TrimSpace(fallbackTarget),
			Mode:      SecureCellThreadDecisionDelegationModeEscalate,
			DueAt:     &dueAt,
		})
	}
	sort.SliceStable(normalized, func(i, j int) bool {
		if normalized[i].DueAt.Equal(*normalized[j].DueAt) {
			return normalized[i].TierID < normalized[j].TierID
		}
		return normalized[i].DueAt.Before(*normalized[j].DueAt)
	})
	for idx := 1; idx < len(normalized); idx++ {
		if normalized[idx].DueAt.Before(*normalized[idx-1].DueAt) {
			return nil, fmt.Errorf("securecells/service: escalation ladder due_at values must be increasing")
		}
	}
	return normalized, nil
}

func secureCellDecisionEscalationTierIDs(ladder []SecureCellDecisionEscalationTier) []string {
	out := make([]string, 0, len(ladder))
	for _, tier := range ladder {
		if trimmed := strings.TrimSpace(tier.TierID); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func secureCellDecisionEscalationTierTargets(ladder []SecureCellDecisionEscalationTier) []string {
	out := make([]string, 0, len(ladder))
	for _, tier := range ladder {
		if trimmed := strings.TrimSpace(tier.TargetDID); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func secureCellDecisionHasEscalationTier(decision SecureCellThreadDecision, tier SecureCellDecisionEscalationTier) bool {
	for _, delegation := range decision.Delegations {
		if delegation.Mode != tier.Mode {
			continue
		}
		if tierID := strings.TrimSpace(delegation.Metadata["automation_tier_id"]); tierID != "" {
			if tierID == strings.TrimSpace(tier.TierID) {
				return true
			}
			continue
		}
		if strings.EqualFold(strings.TrimSpace(delegation.ToActorDID), strings.TrimSpace(tier.TargetDID)) {
			return true
		}
	}
	return false
}

func secureCellDecisionNextDueEscalationTier(decision SecureCellThreadDecision, at time.Time) (SecureCellDecisionEscalationTier, bool) {
	for _, tier := range decision.EscalationLadder {
		if tier.DueAt == nil || tier.DueAt.IsZero() || tier.DueAt.After(at) {
			continue
		}
		if secureCellDecisionHasEscalationTier(decision, tier) {
			continue
		}
		return tier, true
	}
	if decision.EscalationDueAt != nil && decision.AutoEscalateToDID != "" && !decision.EscalationDueAt.After(at) && !secureCellDecisionHasDelegation(decision, SecureCellThreadDecisionDelegationModeEscalate, decision.AutoEscalateToDID) {
		return SecureCellDecisionEscalationTier{
			TierID:    "tier_1",
			TargetDID: decision.AutoEscalateToDID,
			Mode:      SecureCellThreadDecisionDelegationModeEscalate,
			DueAt:     cloneUTCTime(decision.EscalationDueAt),
		}, true
	}
	return SecureCellDecisionEscalationTier{}, false
}

func secureCellDecisionOverdueAction(decision SecureCellThreadDecision, at time.Time) (action string, reason string, tierID string, targetDID string, dueAt time.Time, ok bool) {
	if !decisionStatusAllowed(decision.Status, SecureCellThreadDecisionStatusOpen, SecureCellThreadDecisionStatusQuorumFailed) {
		return "", "", "", "", time.Time{}, false
	}
	if decision.ResolutionDueAt != nil && !decision.ResolutionDueAt.After(at) {
		return "close", "resolution_due", "", "", decision.ResolutionDueAt.UTC(), true
	}
	if tier, found := secureCellDecisionNextDueEscalationTier(decision, at); found && tier.DueAt != nil {
		return "escalate", "escalation_tier_due", strings.TrimSpace(tier.TierID), strings.TrimSpace(tier.TargetDID), tier.DueAt.UTC(), true
	}
	return "", "", "", "", time.Time{}, false
}

func secureCellDecisionReferencesParticipant(decision SecureCellThreadDecision, participantDID string) bool {
	participantDID = strings.TrimSpace(participantDID)
	if participantDID == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(decision.ProposedBy), participantDID) ||
		strings.EqualFold(strings.TrimSpace(decision.ApprovedBy), participantDID) ||
		strings.EqualFold(strings.TrimSpace(decision.QuorumFailedBy), participantDID) ||
		strings.EqualFold(strings.TrimSpace(decision.ClosedBy), participantDID) ||
		strings.EqualFold(strings.TrimSpace(decision.AutoEscalateToDID), participantDID) {
		return true
	}
	if secureCellStringSliceContains(decision.EligibleApproverDIDs, participantDID) || secureCellStringSliceContains(secureCellDecisionEscalationTierTargets(decision.EscalationLadder), participantDID) {
		return true
	}
	for _, vote := range decision.ApprovalVotes {
		if strings.EqualFold(strings.TrimSpace(vote.ActorDID), participantDID) {
			return true
		}
	}
	for _, comment := range decision.Comments {
		if strings.EqualFold(strings.TrimSpace(comment.ActorDID), participantDID) {
			return true
		}
	}
	for _, delegation := range decision.Delegations {
		if strings.EqualFold(strings.TrimSpace(delegation.FromActorDID), participantDID) || strings.EqualFold(strings.TrimSpace(delegation.ToActorDID), participantDID) {
			return true
		}
	}
	return false
}

func secureCellDecisionTitle(decisions []SecureCellThreadDecision, decisionID string) string {
	decisionID = strings.TrimSpace(decisionID)
	for _, decision := range decisions {
		if strings.TrimSpace(decision.ID) == decisionID {
			return decision.Title
		}
	}
	return ""
}

func secureCellDecisionLookup(decisions []SecureCellThreadDecision, decisionID string) (*SecureCellThreadDecision, bool) {
	decisionID = strings.TrimSpace(decisionID)
	if decisionID == "" {
		return nil, false
	}
	for idx := range decisions {
		if strings.TrimSpace(decisions[idx].ID) == decisionID {
			return &decisions[idx], true
		}
	}
	return nil, false
}

func secureCellTransitionAutomatedDecisionAction(transition SecureCellTransition) bool {
	if strings.TrimSpace(transition.DecisionID) == "" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(transition.Metadata["decision_sweep_mode"]), "automated")
}

func parseSecureCellTransitionDueAt(metadata map[string]string) *time.Time {
	if metadata == nil {
		return nil
	}
	raw := strings.TrimSpace(metadata["decision_sweep_due_at"])
	if raw == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return nil
	}
	return &parsed
}

func secureCellStringSliceContains(values []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}

func firstNonEmptyDecisionRoles(primary []string, fallback []string) []string {
	if len(uniqueSecureCellDecisionRoles(primary)) > 0 {
		return uniqueSecureCellDecisionRoles(primary)
	}
	return uniqueSecureCellDecisionRoles(fallback)
}

func secureCellDecisionMissingRequiredRoles(decision SecureCellThreadDecision) []string {
	if len(decision.RequiredApproverRoles) == 0 {
		return nil
	}
	satisfied := make(map[string]struct{}, len(decision.ApprovalVotes))
	for _, vote := range decision.ApprovalVotes {
		if vote.Choice != SecureCellThreadDecisionVoteChoiceApprove {
			continue
		}
		role := strings.TrimSpace(strings.ToLower(vote.ActorRole))
		if role != "" {
			satisfied[role] = struct{}{}
		}
	}
	var missing []string
	for _, requiredRole := range uniqueSecureCellDecisionRoles(decision.RequiredApproverRoles) {
		if _, ok := satisfied[requiredRole]; !ok {
			missing = append(missing, requiredRole)
		}
	}
	return missing
}

func secureCellDecisionApprovalSatisfied(decision SecureCellThreadDecision) bool {
	approveVotes := 0
	for _, vote := range decision.ApprovalVotes {
		if vote.Choice == SecureCellThreadDecisionVoteChoiceApprove {
			approveVotes++
		}
	}
	if approveVotes < decisionApprovalThreshold(decision) {
		return false
	}
	return len(secureCellDecisionMissingRequiredRoles(decision)) == 0
}

func secureCellDecisionHasDelegation(decision SecureCellThreadDecision, mode SecureCellThreadDecisionDelegationMode, targetDID string) bool {
	targetDID = strings.TrimSpace(targetDID)
	for _, delegation := range decision.Delegations {
		if delegation.Mode == mode && strings.TrimSpace(delegation.ToActorDID) == targetDID {
			return true
		}
	}
	return false
}

func secureCellContainedSharedOutputTotal(outputs []SecureCellSharedOutput) int {
	total := 0
	for _, output := range outputs {
		if output.ContainmentStatus == SecureCellArtifactContainmentStatusContained {
			total++
		}
	}
	return total
}

func secureCellContainedSessionExchangeTotal(exchanges []SecureCellSessionExchange) int {
	total := 0
	for _, item := range exchanges {
		if item.ContainmentStatus == SecureCellArtifactContainmentStatusContained {
			total++
		}
	}
	return total
}

func secureCellDecisionContainedSharedOutputIDs(outputs []SecureCellSharedOutput, decisionID string) []string {
	decisionID = strings.TrimSpace(decisionID)
	ids := make([]string, 0)
	for _, output := range outputs {
		if strings.TrimSpace(output.ContainmentDecisionID) == decisionID && output.ContainmentStatus == SecureCellArtifactContainmentStatusContained {
			ids = append(ids, output.ID)
		}
	}
	return ids
}

func secureCellDecisionContainedSessionExchangeIDs(exchanges []SecureCellSessionExchange, decisionID string) []string {
	decisionID = strings.TrimSpace(decisionID)
	ids := make([]string, 0)
	for _, item := range exchanges {
		if strings.TrimSpace(item.ContainmentDecisionID) == decisionID && item.ContainmentStatus == SecureCellArtifactContainmentStatusContained {
			ids = append(ids, item.ID)
		}
	}
	return ids
}

func firstNonEmptyArtifactContainmentStatus(values ...SecureCellArtifactContainmentStatus) SecureCellArtifactContainmentStatus {
	for _, value := range values {
		if strings.TrimSpace(string(value)) != "" {
			return value
		}
	}
	return ""
}

func lastSecureCellTransition(result *SecureCellResult) *SecureCellTransition {
	if result == nil || len(result.Transitions) == 0 {
		return nil
	}
	return &result.Transitions[len(result.Transitions)-1]
}

func sessionsByStatus(sessions []SecureCellSession, status SecureCellSessionStatus) []SecureCellSession {
	filtered := make([]SecureCellSession, 0, len(sessions))
	for _, session := range sessions {
		if session.Status == status {
			filtered = append(filtered, session)
		}
	}
	return filtered
}

func threadsByStatus(threads []SecureCellSessionThread, status SecureCellThreadStatus) []SecureCellSessionThread {
	filtered := make([]SecureCellSessionThread, 0, len(threads))
	for _, thread := range threads {
		if thread.Status == status {
			filtered = append(filtered, thread)
		}
	}
	return filtered
}

func threadsForSession(threads []SecureCellSessionThread, sessionID string) []SecureCellSessionThread {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil
	}
	filtered := make([]SecureCellSessionThread, 0, len(threads))
	for _, thread := range threads {
		if strings.TrimSpace(thread.SessionID) == sessionID {
			filtered = append(filtered, thread)
		}
	}
	return filtered
}

func decisionsByStatus(decisions []SecureCellThreadDecision, status SecureCellThreadDecisionStatus) []SecureCellThreadDecision {
	filtered := make([]SecureCellThreadDecision, 0, len(decisions))
	for _, decision := range decisions {
		if decision.Status == status {
			filtered = append(filtered, decision)
		}
	}
	return filtered
}

func decisionsForSession(decisions []SecureCellThreadDecision, sessionID string) []SecureCellThreadDecision {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil
	}
	filtered := make([]SecureCellThreadDecision, 0, len(decisions))
	for _, decision := range decisions {
		if strings.TrimSpace(decision.SessionID) == sessionID {
			filtered = append(filtered, decision)
		}
	}
	return filtered
}

func decisionsForThread(decisions []SecureCellThreadDecision, threadID string) []SecureCellThreadDecision {
	threadID = strings.TrimSpace(threadID)
	if threadID == "" {
		return nil
	}
	filtered := make([]SecureCellThreadDecision, 0, len(decisions))
	for _, decision := range decisions {
		if strings.TrimSpace(decision.ThreadID) == threadID {
			filtered = append(filtered, decision)
		}
	}
	return filtered
}

func secureCellSessionHasParticipant(session SecureCellSession, participantDID string) bool {
	for _, did := range session.ParticipantDIDs {
		if strings.TrimSpace(did) == strings.TrimSpace(participantDID) {
			return true
		}
	}
	return false
}

func secureCellActorAllowed(run *secureCellRun, actorDID string, activeOnly bool) bool {
	actorDID = strings.TrimSpace(actorDID)
	if run == nil || run.request.OwnerIdentity == nil || actorDID == "" {
		return false
	}
	if run.request.OwnerIdentity.AgentID() == actorDID {
		return true
	}
	state, ok := participantStateForResult(run.result, actorDID)
	if !ok {
		return false
	}
	if !activeOnly {
		return true
	}
	return state.Status == SecureCellParticipantStatusActive
}

func secureCellSessionActorAllowed(run *secureCellRun, session SecureCellSession, actorDID string) bool {
	if !secureCellActorAllowed(run, actorDID, false) {
		return false
	}
	if run != nil && run.request.OwnerIdentity != nil && run.request.OwnerIdentity.AgentID() == strings.TrimSpace(actorDID) {
		return true
	}
	for _, participantDID := range session.ParticipantDIDs {
		if strings.TrimSpace(participantDID) == strings.TrimSpace(actorDID) {
			state, ok := participantStateForResult(run.result, actorDID)
			return ok && state.Status == SecureCellParticipantStatusActive
		}
	}
	return false
}

func secureCellThreadActorAllowed(run *secureCellRun, thread SecureCellSessionThread, actorDID string) bool {
	if !secureCellActorAllowed(run, actorDID, false) {
		return false
	}
	if run != nil && run.request.OwnerIdentity != nil && run.request.OwnerIdentity.AgentID() == strings.TrimSpace(actorDID) {
		return true
	}
	for _, participantDID := range thread.ParticipantDIDs {
		if strings.TrimSpace(participantDID) == strings.TrimSpace(actorDID) {
			state, ok := participantStateForResult(run.result, actorDID)
			return ok && state.Status == SecureCellParticipantStatusActive
		}
	}
	return false
}

func removeSecureCellString(values []string, target string) []string {
	target = strings.TrimSpace(target)
	if len(values) == 0 || target == "" {
		return append([]string(nil), values...)
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			continue
		}
		out = append(out, value)
	}
	return out
}

func secureCellResolveSessionParticipants(states []SecureCellParticipantState, requested []string) ([]string, error) {
	activeParticipants := participantsByStatus(states, SecureCellParticipantStatusActive)
	activeSet := make(map[string]struct{}, len(activeParticipants))
	defaultParticipants := make([]string, 0, len(activeParticipants))
	for _, participant := range activeParticipants {
		activeSet[participant.ParticipantDID] = struct{}{}
		defaultParticipants = append(defaultParticipants, participant.ParticipantDID)
	}
	if len(defaultParticipants) == 0 {
		return nil, fmt.Errorf("securecells/service: at least one active participant is required to start a session")
	}
	requested = uniqueTrimmedStrings(requested)
	if len(requested) == 0 {
		return defaultParticipants, nil
	}
	for _, participantDID := range requested {
		if _, ok := activeSet[participantDID]; !ok {
			return nil, fmt.Errorf("securecells/service: %w: session participant %q is not active in the secure cell", ErrParticipantNotFound, participantDID)
		}
	}
	return requested, nil
}

func secureCellResolveSessionRecipients(states []SecureCellParticipantState, session SecureCellSession, requested []string) ([]string, error) {
	sessionSet := make(map[string]struct{}, len(session.ParticipantDIDs))
	for _, participantDID := range session.ParticipantDIDs {
		sessionSet[strings.TrimSpace(participantDID)] = struct{}{}
	}
	activeSet := make(map[string]struct{}, len(states))
	for _, state := range states {
		if state.Status == SecureCellParticipantStatusActive {
			activeSet[strings.TrimSpace(state.ParticipantDID)] = struct{}{}
		}
	}
	requested = uniqueTrimmedStrings(requested)
	if len(requested) == 0 {
		requested = append([]string(nil), session.ParticipantDIDs...)
	}
	if len(requested) == 0 {
		return nil, fmt.Errorf("securecells/service: session %q has no active recipients", session.ID)
	}
	for _, participantDID := range requested {
		if _, ok := sessionSet[participantDID]; !ok {
			return nil, fmt.Errorf("securecells/service: participant %q is not part of session %q", participantDID, session.ID)
		}
		if _, ok := activeSet[participantDID]; !ok {
			return nil, fmt.Errorf("securecells/service: participant %q is not active in secure cell %q", participantDID, session.ID)
		}
	}
	return requested, nil
}

func secureCellResolveSessionDataClasses(policyConfig SecureCellPolicy, requested []string) ([]string, error) {
	allowed := uniqueTrimmedStrings(policyConfig.DataClasses)
	requested = uniqueTrimmedStrings(requested)
	if len(requested) == 0 {
		return allowed, nil
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, dataClass := range allowed {
		allowedSet[dataClass] = struct{}{}
	}
	for _, dataClass := range requested {
		if _, ok := allowedSet[dataClass]; !ok {
			return nil, fmt.Errorf("securecells/service: data class %q is not permitted by secure cell policy", dataClass)
		}
	}
	return requested, nil
}

func secureCellResolveThreadParticipants(states []SecureCellParticipantState, session SecureCellSession, requested []string) ([]string, error) {
	requested = uniqueTrimmedStrings(requested)
	sessionSet := make(map[string]struct{}, len(session.ParticipantDIDs))
	activeSet := make(map[string]struct{}, len(states))
	defaultParticipants := make([]string, 0, len(session.ParticipantDIDs))
	for _, participantDID := range session.ParticipantDIDs {
		sessionSet[strings.TrimSpace(participantDID)] = struct{}{}
		defaultParticipants = append(defaultParticipants, strings.TrimSpace(participantDID))
	}
	for _, state := range states {
		if state.Status == SecureCellParticipantStatusActive {
			activeSet[strings.TrimSpace(state.ParticipantDID)] = struct{}{}
		}
	}
	if len(requested) == 0 {
		return defaultParticipants, nil
	}
	for _, participantDID := range requested {
		if _, ok := sessionSet[participantDID]; !ok {
			return nil, fmt.Errorf("securecells/service: %w: thread participant %q is not part of session %q", ErrSessionParticipantNotFound, participantDID, session.ID)
		}
		if _, ok := activeSet[participantDID]; !ok {
			return nil, fmt.Errorf("securecells/service: %w: thread participant %q is not active in the secure cell", ErrParticipantNotFound, participantDID)
		}
	}
	return requested, nil
}

func secureCellResolveThreadDataClasses(session SecureCellSession, requested []string) ([]string, error) {
	allowed := uniqueTrimmedStrings(session.DataClasses)
	requested = uniqueTrimmedStrings(requested)
	if len(requested) == 0 {
		return allowed, nil
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, dataClass := range allowed {
		allowedSet[dataClass] = struct{}{}
	}
	for _, dataClass := range requested {
		if _, ok := allowedSet[dataClass]; !ok {
			return nil, fmt.Errorf("securecells/service: data class %q is not permitted by thread policy", dataClass)
		}
	}
	return requested, nil
}

func secureCellResolveOutputClassification(policyConfig SecureCellPolicy, session SecureCellSession, classification string) (string, error) {
	classification = strings.TrimSpace(classification)
	allowed := session.DataClasses
	if len(allowed) == 0 {
		allowed = policyConfig.DataClasses
	}
	allowed = uniqueTrimmedStrings(allowed)
	if classification == "" {
		if len(allowed) > 0 {
			return allowed[0], nil
		}
		return "confidential", nil
	}
	for _, allowedClass := range allowed {
		if classification == allowedClass {
			return classification, nil
		}
	}
	return "", fmt.Errorf("securecells/service: output classification %q is not permitted in session %q", classification, session.ID)
}

func secureCellResolveThreadClassification(thread SecureCellSessionThread, classification string) (string, error) {
	classification = strings.TrimSpace(classification)
	allowed := uniqueTrimmedStrings(thread.DataClasses)
	if classification == "" {
		if len(allowed) > 0 {
			return allowed[0], nil
		}
		return "confidential", nil
	}
	for _, allowedClass := range allowed {
		if classification == allowedClass {
			return classification, nil
		}
	}
	return "", fmt.Errorf("securecells/service: thread classification %q is not permitted in thread %q", classification, thread.ID)
}

func secureCellResolveThreadDecisionClassification(thread SecureCellSessionThread, classification string) (string, error) {
	return secureCellResolveThreadClassification(thread, classification)
}

func secureCellResolveThreadRecipients(states []SecureCellParticipantState, thread SecureCellSessionThread, requested []string) ([]string, error) {
	threadSet := make(map[string]struct{}, len(thread.ParticipantDIDs))
	activeSet := make(map[string]struct{}, len(states))
	for _, participantDID := range thread.ParticipantDIDs {
		threadSet[strings.TrimSpace(participantDID)] = struct{}{}
	}
	for _, state := range states {
		if state.Status == SecureCellParticipantStatusActive {
			activeSet[strings.TrimSpace(state.ParticipantDID)] = struct{}{}
		}
	}
	requested = uniqueTrimmedStrings(requested)
	if len(requested) == 0 {
		requested = append([]string(nil), thread.ParticipantDIDs...)
	}
	if len(requested) == 0 {
		return nil, fmt.Errorf("securecells/service: thread %q has no active recipients", thread.ID)
	}
	for _, participantDID := range requested {
		if _, ok := threadSet[participantDID]; !ok {
			return nil, fmt.Errorf("securecells/service: participant %q is not part of thread %q", participantDID, thread.ID)
		}
		if _, ok := activeSet[participantDID]; !ok {
			return nil, fmt.Errorf("securecells/service: participant %q is not active in thread %q", participantDID, thread.ID)
		}
	}
	return requested, nil
}

func secureCellResolveThreadDecisionExchangeRefs(session SecureCellSession, thread SecureCellSessionThread, exchanges []SecureCellSessionExchange, requested []string) ([]string, error) {
	requested = uniqueTrimmedStrings(requested)
	if len(requested) == 0 {
		return nil, nil
	}
	allowed := make(map[string]struct{}, len(exchanges))
	for _, exchange := range exchanges {
		if strings.TrimSpace(exchange.SessionID) != strings.TrimSpace(session.ID) {
			continue
		}
		if strings.TrimSpace(exchange.ThreadID) != strings.TrimSpace(thread.ID) {
			continue
		}
		allowed[strings.TrimSpace(exchange.ID)] = struct{}{}
	}
	for _, exchangeID := range requested {
		if _, ok := allowed[exchangeID]; !ok {
			return nil, fmt.Errorf("securecells/service: thread exchange %q is not part of thread %q", exchangeID, thread.ID)
		}
	}
	return requested, nil
}

func secureCellResolveThreadDecisionOutputRefs(session SecureCellSession, outputs []SecureCellSharedOutput, requested []string) ([]string, error) {
	requested = uniqueTrimmedStrings(requested)
	if len(requested) == 0 {
		return nil, nil
	}
	allowed := make(map[string]struct{}, len(outputs))
	for _, output := range outputs {
		if strings.TrimSpace(output.SessionID) != strings.TrimSpace(session.ID) {
			continue
		}
		allowed[strings.TrimSpace(output.ID)] = struct{}{}
	}
	for _, outputID := range requested {
		if _, ok := allowed[outputID]; !ok {
			return nil, fmt.Errorf("securecells/service: shared output %q is not part of session %q", outputID, session.ID)
		}
	}
	return requested, nil
}

func secureCellSessionID(req SecureCellRequest, result *SecureCellResult, name string, participantDIDs []string) string {
	fingerprint := struct {
		CellID          string   `json:"cell_id"`
		Sequence        int      `json:"sequence"`
		Name            string   `json:"name"`
		ParticipantDIDs []string `json:"participant_dids,omitempty"`
		Timestamp       string   `json:"timestamp"`
	}{
		CellID:          cellID(req),
		Sequence:        len(result.Sessions) + 1,
		Name:            strings.TrimSpace(name),
		ParticipantDIDs: append([]string(nil), participantDIDs...),
		Timestamp:       time.Now().UTC().Format(time.RFC3339Nano),
	}
	return fmt.Sprintf("session-%x", sha256.Sum256(mustJSON(fingerprint)))
}

func secureCellSharedOutputID(req SecureCellRequest, session SecureCellSession, name, actorDID string, existing []SecureCellSharedOutput) string {
	fingerprint := struct {
		CellID    string `json:"cell_id"`
		SessionID string `json:"session_id"`
		Sequence  int    `json:"sequence"`
		Name      string `json:"name"`
		ActorDID  string `json:"actor_did"`
		Timestamp string `json:"timestamp"`
	}{
		CellID:    cellID(req),
		SessionID: session.ID,
		Sequence:  len(existing) + 1,
		Name:      strings.TrimSpace(name),
		ActorDID:  strings.TrimSpace(actorDID),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
	return fmt.Sprintf("shared-output-%x", sha256.Sum256(mustJSON(fingerprint)))
}

func secureCellSessionExchangeID(req SecureCellRequest, session SecureCellSession, name, actorDID string, existing []SecureCellSessionExchange) string {
	fingerprint := struct {
		CellID    string `json:"cell_id"`
		SessionID string `json:"session_id"`
		Sequence  int    `json:"sequence"`
		Name      string `json:"name"`
		ActorDID  string `json:"actor_did"`
		Timestamp string `json:"timestamp"`
	}{
		CellID:    cellID(req),
		SessionID: session.ID,
		Sequence:  len(existing) + 1,
		Name:      strings.TrimSpace(name),
		ActorDID:  strings.TrimSpace(actorDID),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
	return fmt.Sprintf("session-exchange-%x", sha256.Sum256(mustJSON(fingerprint)))
}

func secureCellSessionThreadID(req SecureCellRequest, session SecureCellSession, name string, participantDIDs []string, existing []SecureCellSessionThread) string {
	fingerprint := struct {
		CellID          string   `json:"cell_id"`
		SessionID       string   `json:"session_id"`
		Sequence        int      `json:"sequence"`
		Name            string   `json:"name"`
		ParticipantDIDs []string `json:"participant_dids,omitempty"`
		Timestamp       string   `json:"timestamp"`
	}{
		CellID:          cellID(req),
		SessionID:       session.ID,
		Sequence:        len(existing) + 1,
		Name:            strings.TrimSpace(name),
		ParticipantDIDs: append([]string(nil), participantDIDs...),
		Timestamp:       time.Now().UTC().Format(time.RFC3339Nano),
	}
	return fmt.Sprintf("session-thread-%x", sha256.Sum256(mustJSON(fingerprint)))
}

func secureCellThreadMessageID(req SecureCellRequest, session SecureCellSession, thread SecureCellSessionThread, name, actorDID string, existing []SecureCellSessionExchange) string {
	fingerprint := struct {
		CellID    string `json:"cell_id"`
		SessionID string `json:"session_id"`
		ThreadID  string `json:"thread_id"`
		Sequence  int    `json:"sequence"`
		Name      string `json:"name"`
		ActorDID  string `json:"actor_did"`
		Timestamp string `json:"timestamp"`
	}{
		CellID:    cellID(req),
		SessionID: session.ID,
		ThreadID:  thread.ID,
		Sequence:  len(existing) + 1,
		Name:      strings.TrimSpace(name),
		ActorDID:  strings.TrimSpace(actorDID),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
	return fmt.Sprintf("thread-message-%x", sha256.Sum256(mustJSON(fingerprint)))
}

func secureCellThreadDecisionID(req SecureCellRequest, session SecureCellSession, thread SecureCellSessionThread, title, actorDID string, existing []SecureCellThreadDecision) string {
	fingerprint := struct {
		CellID    string `json:"cell_id"`
		SessionID string `json:"session_id"`
		ThreadID  string `json:"thread_id"`
		Sequence  int    `json:"sequence"`
		Title     string `json:"title"`
		ActorDID  string `json:"actor_did"`
		Timestamp string `json:"timestamp"`
	}{
		CellID:    cellID(req),
		SessionID: session.ID,
		ThreadID:  thread.ID,
		Sequence:  len(existing) + 1,
		Title:     strings.TrimSpace(title),
		ActorDID:  strings.TrimSpace(actorDID),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
	return fmt.Sprintf("thread-decision-%x", sha256.Sum256(mustJSON(fingerprint)))
}

func secureCellThreadDecisionVoteID(req SecureCellRequest, decision SecureCellThreadDecision, actorDID string, existingCount int) string {
	fingerprint := struct {
		CellID     string `json:"cell_id"`
		DecisionID string `json:"decision_id"`
		Sequence   int    `json:"sequence"`
		ActorDID   string `json:"actor_did"`
		Timestamp  string `json:"timestamp"`
	}{
		CellID:     cellID(req),
		DecisionID: decision.ID,
		Sequence:   existingCount + 1,
		ActorDID:   strings.TrimSpace(actorDID),
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	return fmt.Sprintf("thread-decision-vote-%x", sha256.Sum256(mustJSON(fingerprint)))
}

func secureCellThreadDecisionCommentID(req SecureCellRequest, decision SecureCellThreadDecision, actorDID, comment string, existingCount int) string {
	fingerprint := struct {
		CellID     string `json:"cell_id"`
		DecisionID string `json:"decision_id"`
		Sequence   int    `json:"sequence"`
		ActorDID   string `json:"actor_did"`
		Comment    string `json:"comment"`
		Timestamp  string `json:"timestamp"`
	}{
		CellID:     cellID(req),
		DecisionID: decision.ID,
		Sequence:   existingCount + 1,
		ActorDID:   strings.TrimSpace(actorDID),
		Comment:    strings.TrimSpace(comment),
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	return fmt.Sprintf("thread-decision-comment-%x", sha256.Sum256(mustJSON(fingerprint)))
}

func secureCellThreadDecisionDelegationID(req SecureCellRequest, decision SecureCellThreadDecision, mode SecureCellThreadDecisionDelegationMode, actorDID, targetDID string, existingCount int) string {
	fingerprint := struct {
		CellID     string `json:"cell_id"`
		DecisionID string `json:"decision_id"`
		Sequence   int    `json:"sequence"`
		Mode       string `json:"mode"`
		ActorDID   string `json:"actor_did"`
		TargetDID  string `json:"target_did"`
		Timestamp  string `json:"timestamp"`
	}{
		CellID:     cellID(req),
		DecisionID: decision.ID,
		Sequence:   existingCount + 1,
		Mode:       string(mode),
		ActorDID:   strings.TrimSpace(actorDID),
		TargetDID:  strings.TrimSpace(targetDID),
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	return fmt.Sprintf("thread-decision-delegation-%x", sha256.Sum256(mustJSON(fingerprint)))
}

func secureCellThreadDecisionOutcomeID(req SecureCellRequest, decision SecureCellThreadDecision, title, actorDID string, existingCount int) string {
	fingerprint := struct {
		CellID     string `json:"cell_id"`
		DecisionID string `json:"decision_id"`
		Sequence   int    `json:"sequence"`
		Title      string `json:"title"`
		ActorDID   string `json:"actor_did"`
		Timestamp  string `json:"timestamp"`
	}{
		CellID:     cellID(req),
		DecisionID: decision.ID,
		Sequence:   existingCount + 1,
		Title:      strings.TrimSpace(title),
		ActorDID:   strings.TrimSpace(actorDID),
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	return fmt.Sprintf("thread-decision-outcome-%x", sha256.Sum256(mustJSON(fingerprint)))
}

func firstNonEmptyDecisionStatus(values ...SecureCellThreadDecisionStatus) SecureCellThreadDecisionStatus {
	for _, value := range values {
		if strings.TrimSpace(string(value)) != "" {
			return value
		}
	}
	return ""
}

func secureCellResolveOutputIntegrityHash(share SecureCellSessionShareRequest, outputID, sessionID, actorDID string, sharedWith []string) string {
	if trimmed := strings.TrimSpace(share.IntegrityHash); trimmed != "" {
		return trimmed
	}
	sum := sha256.Sum256(mustJSON(struct {
		OutputID       string            `json:"output_id"`
		SessionID      string            `json:"session_id"`
		Name           string            `json:"name"`
		ArtifactType   string            `json:"artifact_type"`
		Classification string            `json:"classification"`
		Resource       string            `json:"resource"`
		Summary        string            `json:"summary"`
		ActorDID       string            `json:"actor_did"`
		SharedWith     []string          `json:"shared_with,omitempty"`
		Metadata       map[string]string `json:"metadata,omitempty"`
	}{
		OutputID:       outputID,
		SessionID:      sessionID,
		Name:           strings.TrimSpace(share.Name),
		ArtifactType:   strings.TrimSpace(share.ArtifactType),
		Classification: strings.TrimSpace(share.Classification),
		Resource:       strings.TrimSpace(share.Resource),
		Summary:        strings.TrimSpace(share.Summary),
		ActorDID:       strings.TrimSpace(actorDID),
		SharedWith:     append([]string(nil), sharedWith...),
		Metadata:       cloneStringMap(share.Metadata),
	}))
	return hex.EncodeToString(sum[:])
}

func secureCellResolveExchangeIntegrityHash(exchange SecureCellSessionExchangeRequest, exchangeID, sessionID, actorDID string, recipients []string) string {
	if trimmed := strings.TrimSpace(exchange.IntegrityHash); trimmed != "" {
		return trimmed
	}
	sum := sha256.Sum256(mustJSON(struct {
		ExchangeID     string            `json:"exchange_id"`
		SessionID      string            `json:"session_id"`
		Name           string            `json:"name"`
		ExchangeType   string            `json:"exchange_type"`
		Classification string            `json:"classification"`
		Resource       string            `json:"resource"`
		Summary        string            `json:"summary"`
		ActorDID       string            `json:"actor_did"`
		Recipients     []string          `json:"recipients,omitempty"`
		Metadata       map[string]string `json:"metadata,omitempty"`
	}{
		ExchangeID:     exchangeID,
		SessionID:      sessionID,
		Name:           strings.TrimSpace(exchange.Name),
		ExchangeType:   strings.TrimSpace(exchange.ExchangeType),
		Classification: strings.TrimSpace(exchange.Classification),
		Resource:       strings.TrimSpace(exchange.Resource),
		Summary:        strings.TrimSpace(exchange.Summary),
		ActorDID:       strings.TrimSpace(actorDID),
		Recipients:     append([]string(nil), recipients...),
		Metadata:       cloneStringMap(exchange.Metadata),
	}))
	return hex.EncodeToString(sum[:])
}

func secureCellResolveThreadMessageIntegrityHash(message SecureCellThreadMessageRequest, exchangeID, sessionID, threadID, actorDID string, recipients []string) string {
	if trimmed := strings.TrimSpace(message.IntegrityHash); trimmed != "" {
		return trimmed
	}
	sum := sha256.Sum256(mustJSON(struct {
		ExchangeID     string            `json:"exchange_id"`
		SessionID      string            `json:"session_id"`
		ThreadID       string            `json:"thread_id"`
		Name           string            `json:"name"`
		ExchangeType   string            `json:"exchange_type"`
		Classification string            `json:"classification"`
		Resource       string            `json:"resource"`
		Summary        string            `json:"summary"`
		ActorDID       string            `json:"actor_did"`
		Recipients     []string          `json:"recipients,omitempty"`
		Metadata       map[string]string `json:"metadata,omitempty"`
	}{
		ExchangeID:     exchangeID,
		SessionID:      sessionID,
		ThreadID:       threadID,
		Name:           strings.TrimSpace(message.Name),
		ExchangeType:   strings.TrimSpace(message.ExchangeType),
		Classification: strings.TrimSpace(message.Classification),
		Resource:       strings.TrimSpace(message.Resource),
		Summary:        strings.TrimSpace(message.Summary),
		ActorDID:       strings.TrimSpace(actorDID),
		Recipients:     append([]string(nil), recipients...),
		Metadata:       cloneStringMap(message.Metadata),
	}))
	return hex.EncodeToString(sum[:])
}

func secureCellResolveThreadDecisionOutcomeIntegrityHash(req SecureCellThreadDecisionOutcomeRequest, decision SecureCellThreadDecision, title, classification, outcomeType, actorDID string, outputIDs, exchangeIDs []string) string {
	sum := sha256.Sum256(mustJSON(struct {
		DecisionID         string            `json:"decision_id"`
		Title              string            `json:"title"`
		Summary            string            `json:"summary"`
		Classification     string            `json:"classification"`
		OutcomeType        string            `json:"outcome_type"`
		ActorDID           string            `json:"actor_did"`
		RelatedOutputIDs   []string          `json:"related_output_ids,omitempty"`
		RelatedExchangeIDs []string          `json:"related_exchange_ids,omitempty"`
		Metadata           map[string]string `json:"metadata,omitempty"`
	}{
		DecisionID:         decision.ID,
		Title:              strings.TrimSpace(title),
		Summary:            strings.TrimSpace(req.Summary),
		Classification:     strings.TrimSpace(classification),
		OutcomeType:        strings.TrimSpace(outcomeType),
		ActorDID:           strings.TrimSpace(actorDID),
		RelatedOutputIDs:   append([]string(nil), outputIDs...),
		RelatedExchangeIDs: append([]string(nil), exchangeIDs...),
		Metadata:           cloneStringMap(req.Metadata),
	}))
	return hex.EncodeToString(sum[:])
}

func secureCellBuildOutputCustody(producedBy string, sharedWith []string) ([]evidence.CustodyEntry, error) {
	chain, err := evidence.RecordCreation(strings.TrimSpace(producedBy))
	if err != nil {
		return nil, err
	}
	chain, err = evidence.RecordExport(chain, strings.TrimSpace(producedBy))
	if err != nil {
		return nil, err
	}
	for _, recipient := range uniqueTrimmedStrings(sharedWith) {
		if recipient == strings.TrimSpace(producedBy) {
			continue
		}
		chain, err = evidence.RecordAccess(chain, recipient)
		if err != nil {
			return nil, err
		}
	}
	return chain, nil
}

func uniqueTrimmedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func uniqueSecureCellStrings(values []string) []string {
	return uniqueTrimmedStrings(values)
}

func joinSecureCellDecisionVoteChoices(values []SecureCellThreadDecisionVoteChoice) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(values))
	for _, value := range normalizeSecureCellDecisionVoteChoices(values) {
		parts = append(parts, string(value))
	}
	return strings.Join(parts, ",")
}

func cloneUTCTime(in *time.Time) *time.Time {
	if in == nil || in.IsZero() {
		return nil
	}
	value := in.UTC()
	return &value
}

func normalizeSecureCellThreshold(value int) int {
	if value <= 0 {
		return 1
	}
	return value
}

func firstNonEmptyDecisionRefs(primary []string, fallback []string) []string {
	if len(uniqueTrimmedStrings(primary)) > 0 {
		return uniqueTrimmedStrings(primary)
	}
	return uniqueTrimmedStrings(fallback)
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
				secureCellFederationInviteAction,
				secureCellFederationAcceptAction,
				secureCellFederationRevokeAction,
				secureCellFederationCounterproposeAction,
				secureCellFederationCounterproposalEscalateAction,
				secureCellFederationCounterproposalApproveAction,
				secureCellFederationCounterproposalRejectAction,
				secureCellFederationContractRenewAction,
				secureCellFederationContractSuspendAction,
				secureCellFederationContractResumeAction,
				secureCellFederationContractRevokeAction,
				secureCellFederationAssuranceIntakeAction,
				secureCellFederationIncidentPublishAction,
				secureCellFederationIncidentResolveAction,
				secureCellFederationIncidentIntakeAction,
				secureCellFederationIncidentContainAction,
				secureCellFederationIncidentResponseAcknowledgeAction,
				secureCellFederationIncidentResponseEscalateAction,
				secureCellFederationIncidentRemediationAttestAction,
				secureCellFederationIncidentRemediationVerifyAction,
				secureCellFederationIncidentClosureAttestAction,
				secureCellFederationIncidentResponseDisputeAction,
				secureCellFederationIncidentDirectiveIssueAction,
				secureCellFederationIncidentDirectiveAcknowledgeAction,
				secureCellFederationIncidentDirectiveCompleteAction,
				secureCellFederationIncidentDirectiveVerifyAction,
				secureCellFederationIncidentDirectiveExtensionRequestAction,
				secureCellFederationIncidentDirectiveExtensionApproveAction,
				secureCellFederationIncidentDirectiveExtensionRejectAction,
				secureCellFederationIncidentDirectiveExtensionDisputeAction,
				secureCellFederationIncidentDirectiveExtensionResolveAction,
				secureCellFederationIncidentDirectiveExtensionDelegateReviewAction,
				secureCellFederationIncidentDirectiveExtensionDelegateResolutionAction,
				secureCellFederationIncidentDirectiveExtensionAppealAction,
				secureCellFederationIncidentDirectiveExtensionAppealRuleAction,
				secureCellFederationIncidentDirectiveExtensionAppealDelegateReviewAction,
				secureCellFederationIncidentDirectiveExtensionAppealRecuseAction,
				secureCellFederationIncidentDirectiveExtensionAppealRehearAction,
				secureCellFederationIncidentDirectiveExtensionAppealIntakeAction,
				secureCellFederationIncidentDirectiveExtensionAppealAcknowledgeAction,
				secureCellFederationIncidentDirectiveExtensionAppealReconcileAckAction,
				secureCellFederationIncidentDirectiveExtensionAppealReconcileDisputeAction,
				secureCellFederationIncidentDirectiveExtensionAppealReconcileResolveAction,
				secureCellFederationIncidentDirectiveExtensionAppealReconcileChallengeAction,
				secureCellFederationIncidentDirectiveExtensionAppealReconcileChallengeDelegateAction,
				secureCellFederationIncidentDirectiveExtensionAppealReconcileRuleAction,
				secureCellFederationIncidentDirectiveExtensionAppealReconcileCounterpartyAckAction,
				secureCellFederationIncidentDirectiveExtensionAppealReconcileCorrectionAttestAction,
				secureCellFederationIncidentDirectiveExtensionAppealReconcileResolutionAttestAction,
				secureCellFederationIncidentDirectiveExtensionAppealReconcileEscalateAction,
				secureCellFederationIncidentReportPlanAction,
				secureCellFederationIncidentReportIntakeAction,
				secureCellFederationIncidentReportAmendAction,
				secureCellFederationIncidentReportSubmitAction,
				secureCellFederationIncidentReportAcknowledgeAction,
				secureCellFederationIncidentReportAmendmentIntakeAction,
				secureCellFederationIncidentReportAmendmentSubmitAction,
				secureCellFederationIncidentReportAmendmentAckAction,
				secureCellFederationIncidentReportReconcileAckAction,
				secureCellFederationIncidentReportReconcileDisputeAction,
				secureCellFederationIncidentReportReconcileResolveAction,
				secureCellFederationIncidentReportAmendmentReconcileAckAction,
				secureCellFederationIncidentReportAmendmentReconcileDisputeAction,
				secureCellFederationIncidentReportAmendmentReconcileResolveAction,
				secureCellFederationIncidentReportAmendmentReconcileCounterpartyAckAction,
				secureCellFederationIncidentReportAmendmentReconcileCorrectionAttestAction,
				secureCellFederationIncidentReportAmendmentReconcileResolutionAttestAction,
				secureCellFederationIncidentReportAmendmentReconcileEscalateAction,
				secureCellSessionStartAction,
				secureCellSessionThreadStartAction,
				secureCellSessionThreadMessageAction,
				secureCellSessionThreadDecisionCreateAction,
				secureCellSessionThreadDecisionApproveAction,
				secureCellSessionThreadDecisionCommentAction,
				secureCellSessionThreadDecisionDelegateAction,
				secureCellSessionThreadDecisionEscalateAction,
				secureCellSessionThreadDecisionOutcomeAction,
				secureCellSessionThreadDecisionContainAction,
				secureCellSessionThreadDecisionResumeAction,
				secureCellSessionThreadDecisionQuarantineAction,
				secureCellSessionThreadDecisionReleaseAction,
				secureCellSessionThreadDecisionCloseAction,
				secureCellSessionExchangeAction,
				secureCellSessionShareAction,
				secureCellSessionCloseAction,
				secureCellSessionPauseAction,
				secureCellSessionResumeAction,
				secureCellSessionQuarantineAction,
				secureCellSessionThreadCloseAction,
				secureCellSessionThreadResumeAction,
				secureCellSessionThreadQuarantineAction,
				secureCellSessionMemberAdmitAction,
				secureCellSessionMemberRemoveAction,
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
			policy.NewAllowRule("secure_cell_federation_invite_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "invite_federation_member"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_accept_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "accept_federation_invitation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_revoke_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "revoke_federation_invitation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_counterpropose_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "counterpropose_federation_invitation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_counterproposal_escalate_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "escalate_federation_counterproposal"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_counterproposal_approve_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "approve_federation_counterproposal"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_counterproposal_reject_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "reject_federation_counterproposal"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_contract_renew_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "renew_federation_contract"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_contract_suspend_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "suspend_federation_contract"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_contract_resume_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "resume_federation_contract"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_contract_revoke_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "revoke_federation_contract"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_assurance_intake_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "intake_federation_assurance"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_publish_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "publish_federation_incident"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_resolve_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "resolve_federation_incident"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_intake_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "intake_federation_incident_bulletin"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_contain_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "contain_federation_incident_artifacts"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_response_acknowledge_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "acknowledge_federation_incident_response"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_response_escalate_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "escalate_federation_incident_response"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_remediation_attest_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "attest_federation_incident_remediation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_remediation_verify_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "verify_federation_incident_remediation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_closure_attest_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "attest_federation_incident_closure"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_response_dispute_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "dispute_federation_incident_response"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_issue_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "issue_federation_incident_directive"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_acknowledge_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "acknowledge_federation_incident_directive"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_complete_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "complete_federation_incident_directive"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_verify_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "verify_federation_incident_directive"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_request_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "request_federation_incident_directive_extension"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_approve_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "approve_federation_incident_directive_extension"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_reject_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "reject_federation_incident_directive_extension"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_dispute_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "dispute_federation_incident_directive_extension"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_resolve_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "resolve_federation_incident_directive_extension_dispute"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_delegate_review_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "delegate_federation_incident_directive_extension_review"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_delegate_resolution_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "delegate_federation_incident_directive_extension_dispute_resolution"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "appeal_federation_incident_directive_extension_dispute"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_rule_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "rule_federation_incident_directive_extension_appeal"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_delegate_review_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "delegate_federation_incident_directive_extension_appeal_review"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_recuse_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "recuse_federation_incident_directive_extension_appeal_review"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_rehear_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "rehear_federation_incident_directive_extension_appeal"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_intake_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "intake_federation_incident_directive_extension_appeal_bundle"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_acknowledge_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "acknowledge_federation_incident_directive_extension_appeal_enforcement"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_reconciliation_acknowledge_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "acknowledge_federation_incident_directive_extension_appeal_reconciliation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_reconciliation_dispute_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "dispute_federation_incident_directive_extension_appeal_reconciliation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_reconciliation_resolve_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "resolve_federation_incident_directive_extension_appeal_reconciliation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_reconciliation_challenge_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "challenge_federation_incident_directive_extension_appeal_reconciliation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_reconciliation_delegate_review_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "delegate_federation_incident_directive_extension_appeal_reconciliation_review"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_reconciliation_rule_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "rule_federation_incident_directive_extension_appeal_reconciliation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "appeal_federation_incident_directive_extension_appeal_reconciliation_challenge"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_rule_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "rule_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_acknowledge_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "acknowledge_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_reconciliation_acknowledge_dispute_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "acknowledge_federation_incident_directive_extension_appeal_reconciliation_dispute"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_reconciliation_attest_correction_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "attest_federation_incident_directive_extension_appeal_reconciliation_correction"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_reconciliation_attest_resolution_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "attest_federation_incident_directive_extension_appeal_reconciliation_resolution"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_directive_extension_appeal_reconciliation_escalate_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "escalate_federation_incident_directive_extension_appeal_reconciliation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_plan_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "plan_federation_incident_report"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_intake_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "intake_federation_incident_report_bundle"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_amend_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "amend_federation_incident_report"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_submit_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "submit_federation_incident_report"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_acknowledge_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "acknowledge_federation_incident_report"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_amendment_intake_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "intake_federation_incident_report_amendment_bundle"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_amendment_submit_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "submit_federation_incident_report_amendment"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_amendment_acknowledge_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "acknowledge_federation_incident_report_amendment"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_reconciliation_acknowledge_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "acknowledge_federation_incident_report_reconciliation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_reconciliation_dispute_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "dispute_federation_incident_report_reconciliation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_reconciliation_resolve_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "resolve_federation_incident_report_reconciliation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_amendment_reconciliation_acknowledge_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "acknowledge_federation_incident_report_amendment_reconciliation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_amendment_reconciliation_dispute_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "dispute_federation_incident_report_amendment_reconciliation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_amendment_reconciliation_resolve_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "resolve_federation_incident_report_amendment_reconciliation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_amendment_reconciliation_dispute_acknowledge_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "acknowledge_federation_incident_report_amendment_reconciliation_dispute"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_amendment_reconciliation_correction_attest_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "attest_federation_incident_report_amendment_reconciliation_correction"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_amendment_reconciliation_resolution_attest_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "attest_federation_incident_report_amendment_reconciliation_resolution"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_federation_incident_report_amendment_reconciliation_escalate_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "escalate_federation_incident_report_amendment_reconciliation"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_start_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "start_session"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_start_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "start_session_thread"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_message_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "message_session_thread"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_decision_create_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "create_thread_decision"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_decision_approve_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "approve_thread_decision"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_decision_comment_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "comment_thread_decision"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_decision_delegate_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "delegate_thread_decision"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_decision_escalate_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "escalate_thread_decision"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_decision_outcome_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "publish_thread_decision_outcome"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_decision_resume_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "resume_thread_decision"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_decision_quarantine_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "quarantine_thread_decision"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_decision_contain_outputs_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "contain_thread_decision_outputs"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_decision_release_outputs_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "release_thread_decision_outputs"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_decision_close_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "close_thread_decision"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_exchange_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "exchange_session_message"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_share_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "share_session_output"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
				{Field: "confidential_compute", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_close_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "close_session"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_pause_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "pause_session"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_resume_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "resume_session"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_quarantine_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "quarantine_session"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_close_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "close_session_thread"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_resume_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "resume_session_thread"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_thread_quarantine_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "quarantine_session_thread"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_member_admit_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "admit_session_member"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
			}),
			policy.NewAllowRule("secure_cell_session_member_remove_allow", []policy.Condition{
				{Field: "cell_stage", Operator: policy.Equals, Value: "remove_session_member"},
				{Field: "tool_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "capability_present", Operator: policy.Equals, Value: "true"},
				{Field: "liability_profile_present", Operator: policy.Equals, Value: "true"},
				{Field: "jurisdiction_allowed", Operator: policy.Equals, Value: "true"},
				{Field: "sponsor_of_record_present", Operator: policy.Equals, Value: "true"},
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
	case "invite_federation_member":
		return secureCellFederationInviteAction
	case "accept_federation_invitation":
		return secureCellFederationAcceptAction
	case "revoke_federation_invitation":
		return secureCellFederationRevokeAction
	case "counterpropose_federation_invitation":
		return secureCellFederationCounterproposeAction
	case "escalate_federation_counterproposal":
		return secureCellFederationCounterproposalEscalateAction
	case "approve_federation_counterproposal":
		return secureCellFederationCounterproposalApproveAction
	case "reject_federation_counterproposal":
		return secureCellFederationCounterproposalRejectAction
	case "renew_federation_contract":
		return secureCellFederationContractRenewAction
	case "suspend_federation_contract":
		return secureCellFederationContractSuspendAction
	case "resume_federation_contract":
		return secureCellFederationContractResumeAction
	case "revoke_federation_contract":
		return secureCellFederationContractRevokeAction
	case "intake_federation_assurance":
		return secureCellFederationAssuranceIntakeAction
	case "publish_federation_incident":
		return secureCellFederationIncidentPublishAction
	case "resolve_federation_incident":
		return secureCellFederationIncidentResolveAction
	case "intake_federation_incident_bulletin":
		return secureCellFederationIncidentIntakeAction
	case "contain_federation_incident_artifacts":
		return secureCellFederationIncidentContainAction
	case "acknowledge_federation_incident_response":
		return secureCellFederationIncidentResponseAcknowledgeAction
	case "escalate_federation_incident_response":
		return secureCellFederationIncidentResponseEscalateAction
	case "attest_federation_incident_remediation":
		return secureCellFederationIncidentRemediationAttestAction
	case "verify_federation_incident_remediation":
		return secureCellFederationIncidentRemediationVerifyAction
	case "attest_federation_incident_closure":
		return secureCellFederationIncidentClosureAttestAction
	case "dispute_federation_incident_response":
		return secureCellFederationIncidentResponseDisputeAction
	case "issue_federation_incident_directive":
		return secureCellFederationIncidentDirectiveIssueAction
	case "acknowledge_federation_incident_directive":
		return secureCellFederationIncidentDirectiveAcknowledgeAction
	case "complete_federation_incident_directive":
		return secureCellFederationIncidentDirectiveCompleteAction
	case "verify_federation_incident_directive":
		return secureCellFederationIncidentDirectiveVerifyAction
	case "request_federation_incident_directive_extension":
		return secureCellFederationIncidentDirectiveExtensionRequestAction
	case "approve_federation_incident_directive_extension":
		return secureCellFederationIncidentDirectiveExtensionApproveAction
	case "reject_federation_incident_directive_extension":
		return secureCellFederationIncidentDirectiveExtensionRejectAction
	case "dispute_federation_incident_directive_extension":
		return secureCellFederationIncidentDirectiveExtensionDisputeAction
	case "resolve_federation_incident_directive_extension_dispute":
		return secureCellFederationIncidentDirectiveExtensionResolveAction
	case "delegate_federation_incident_directive_extension_review":
		return secureCellFederationIncidentDirectiveExtensionDelegateReviewAction
	case "delegate_federation_incident_directive_extension_dispute_resolution":
		return secureCellFederationIncidentDirectiveExtensionDelegateResolutionAction
	case "appeal_federation_incident_directive_extension_dispute":
		return secureCellFederationIncidentDirectiveExtensionAppealAction
	case "rule_federation_incident_directive_extension_appeal":
		return secureCellFederationIncidentDirectiveExtensionAppealRuleAction
	case "delegate_federation_incident_directive_extension_appeal_review":
		return secureCellFederationIncidentDirectiveExtensionAppealDelegateReviewAction
	case "recuse_federation_incident_directive_extension_appeal_review":
		return secureCellFederationIncidentDirectiveExtensionAppealRecuseAction
	case "rehear_federation_incident_directive_extension_appeal":
		return secureCellFederationIncidentDirectiveExtensionAppealRehearAction
	case "intake_federation_incident_directive_extension_appeal_bundle":
		return secureCellFederationIncidentDirectiveExtensionAppealIntakeAction
	case "acknowledge_federation_incident_directive_extension_appeal_enforcement":
		return secureCellFederationIncidentDirectiveExtensionAppealAcknowledgeAction
	case "acknowledge_federation_incident_directive_extension_appeal_reconciliation":
		return secureCellFederationIncidentDirectiveExtensionAppealReconcileAckAction
	case "dispute_federation_incident_directive_extension_appeal_reconciliation":
		return secureCellFederationIncidentDirectiveExtensionAppealReconcileDisputeAction
	case "resolve_federation_incident_directive_extension_appeal_reconciliation":
		return secureCellFederationIncidentDirectiveExtensionAppealReconcileResolveAction
	case "challenge_federation_incident_directive_extension_appeal_reconciliation":
		return secureCellFederationIncidentDirectiveExtensionAppealReconcileChallengeAction
	case "delegate_federation_incident_directive_extension_appeal_reconciliation_review":
		return secureCellFederationIncidentDirectiveExtensionAppealReconcileChallengeDelegateAction
	case "rule_federation_incident_directive_extension_appeal_reconciliation":
		return secureCellFederationIncidentDirectiveExtensionAppealReconcileRuleAction
	case "acknowledge_federation_incident_directive_extension_appeal_reconciliation_dispute":
		return secureCellFederationIncidentDirectiveExtensionAppealReconcileCounterpartyAckAction
	case "attest_federation_incident_directive_extension_appeal_reconciliation_correction":
		return secureCellFederationIncidentDirectiveExtensionAppealReconcileCorrectionAttestAction
	case "attest_federation_incident_directive_extension_appeal_reconciliation_resolution":
		return secureCellFederationIncidentDirectiveExtensionAppealReconcileResolutionAttestAction
	case "escalate_federation_incident_directive_extension_appeal_reconciliation":
		return secureCellFederationIncidentDirectiveExtensionAppealReconcileEscalateAction
	case "plan_federation_incident_report":
		return secureCellFederationIncidentReportPlanAction
	case "intake_federation_incident_report_bundle":
		return secureCellFederationIncidentReportIntakeAction
	case "amend_federation_incident_report":
		return secureCellFederationIncidentReportAmendAction
	case "submit_federation_incident_report":
		return secureCellFederationIncidentReportSubmitAction
	case "acknowledge_federation_incident_report":
		return secureCellFederationIncidentReportAcknowledgeAction
	case "intake_federation_incident_report_amendment_bundle":
		return secureCellFederationIncidentReportAmendmentIntakeAction
	case "submit_federation_incident_report_amendment":
		return secureCellFederationIncidentReportAmendmentSubmitAction
	case "acknowledge_federation_incident_report_amendment":
		return secureCellFederationIncidentReportAmendmentAckAction
	case "acknowledge_federation_incident_report_reconciliation":
		return secureCellFederationIncidentReportReconcileAckAction
	case "dispute_federation_incident_report_reconciliation":
		return secureCellFederationIncidentReportReconcileDisputeAction
	case "resolve_federation_incident_report_reconciliation":
		return secureCellFederationIncidentReportReconcileResolveAction
	case "acknowledge_federation_incident_report_amendment_reconciliation":
		return secureCellFederationIncidentReportAmendmentReconcileAckAction
	case "dispute_federation_incident_report_amendment_reconciliation":
		return secureCellFederationIncidentReportAmendmentReconcileDisputeAction
	case "resolve_federation_incident_report_amendment_reconciliation":
		return secureCellFederationIncidentReportAmendmentReconcileResolveAction
	case "acknowledge_federation_incident_report_amendment_reconciliation_dispute":
		return secureCellFederationIncidentReportAmendmentReconcileCounterpartyAckAction
	case "attest_federation_incident_report_amendment_reconciliation_correction":
		return secureCellFederationIncidentReportAmendmentReconcileCorrectionAttestAction
	case "attest_federation_incident_report_amendment_reconciliation_resolution":
		return secureCellFederationIncidentReportAmendmentReconcileResolutionAttestAction
	case "escalate_federation_incident_report_amendment_reconciliation":
		return secureCellFederationIncidentReportAmendmentReconcileEscalateAction
	case "start_session":
		return secureCellSessionStartAction
	case "start_session_thread":
		return secureCellSessionThreadStartAction
	case "message_session_thread":
		return secureCellSessionThreadMessageAction
	case "create_thread_decision":
		return secureCellSessionThreadDecisionCreateAction
	case "approve_thread_decision":
		return secureCellSessionThreadDecisionApproveAction
	case "comment_thread_decision":
		return secureCellSessionThreadDecisionCommentAction
	case "delegate_thread_decision":
		return secureCellSessionThreadDecisionDelegateAction
	case "escalate_thread_decision":
		return secureCellSessionThreadDecisionEscalateAction
	case "publish_thread_decision_outcome":
		return secureCellSessionThreadDecisionOutcomeAction
	case "contain_thread_decision_outputs":
		return secureCellSessionThreadDecisionContainAction
	case "resume_thread_decision":
		return secureCellSessionThreadDecisionResumeAction
	case "quarantine_thread_decision":
		return secureCellSessionThreadDecisionQuarantineAction
	case "release_thread_decision_outputs":
		return secureCellSessionThreadDecisionReleaseAction
	case "close_thread_decision":
		return secureCellSessionThreadDecisionCloseAction
	case "exchange_session_message":
		return secureCellSessionExchangeAction
	case "share_session_output":
		return secureCellSessionShareAction
	case "close_session":
		return secureCellSessionCloseAction
	case "pause_session":
		return secureCellSessionPauseAction
	case "resume_session":
		return secureCellSessionResumeAction
	case "quarantine_session":
		return secureCellSessionQuarantineAction
	case "close_session_thread":
		return secureCellSessionThreadCloseAction
	case "resume_session_thread":
		return secureCellSessionThreadResumeAction
	case "quarantine_session_thread":
		return secureCellSessionThreadQuarantineAction
	case "admit_session_member":
		return secureCellSessionMemberAdmitAction
	case "remove_session_member":
		return secureCellSessionMemberRemoveAction
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
