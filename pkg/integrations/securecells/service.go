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
	secureCellTool                          = "secure_cells"
	secureCellCreateAction                  = "secure_cells.create"
	secureCellActivateAction                = "secure_cells.activate"
	secureCellSessionStartAction            = "secure_cells.session.start"
	secureCellSessionThreadStartAction      = "secure_cells.session.thread.start"
	secureCellSessionThreadMessageAction    = "secure_cells.session.thread.message"
	secureCellSessionShareAction            = "secure_cells.session.share"
	secureCellSessionExchangeAction         = "secure_cells.session.exchange"
	secureCellSessionCloseAction            = "secure_cells.session.close"
	secureCellSessionPauseAction            = "secure_cells.session.pause"
	secureCellSessionResumeAction           = "secure_cells.session.resume"
	secureCellSessionQuarantineAction       = "secure_cells.session.quarantine"
	secureCellSessionThreadCloseAction      = "secure_cells.session.thread.close"
	secureCellSessionThreadResumeAction     = "secure_cells.session.thread.resume"
	secureCellSessionThreadQuarantineAction = "secure_cells.session.thread.quarantine"
	secureCellSessionMemberAdmitAction      = "secure_cells.session.member.admit"
	secureCellSessionMemberRemoveAction     = "secure_cells.session.member.remove"
	secureCellMemberAdmitAction             = "secure_cells.member.admit"
	secureCellMemberReleaseAction           = "secure_cells.member.release"
	secureCellMemberQuarantineAction        = "secure_cells.member.quarantine"
	secureCellMemberRevokeAction            = "secure_cells.member.revoke"
	secureCellQuarantineExpireAction        = "secure_cells.quarantine.expire"
	secureCellPauseAction                   = "secure_cells.pause"
	secureCellResumeAction                  = "secure_cells.resume"
	secureCellTerminateAction               = "secure_cells.terminate"
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

// SecureCellSealer creates execution seals for secure cells.
type SecureCellSealer interface {
	CreateSeal(ctx context.Context, req sdk.SealRequest) (*sdk.SealResponse, error)
}

// SecureCellPackageSigner signs a portable control-ledger package.
type SecureCellPackageSigner func(ctx context.Context, pkg *evidence.PortableControlLedgerPackage) error

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
	ExchangeIDs     []string               `json:"exchange_ids,omitempty"`
	OpenedAt        time.Time              `json:"opened_at"`
	QuarantinedAt   *time.Time             `json:"quarantined_at,omitempty"`
	ClosedAt        *time.Time             `json:"closed_at,omitempty"`
	UpdatedAt       time.Time              `json:"updated_at"`
	ContainedBy     string                 `json:"contained_by,omitempty"`
	Metadata        map[string]string      `json:"metadata,omitempty"`
}

// SecureCellSessionExchange captures one message or exchange artifact inside a
// governed collaboration session.
type SecureCellSessionExchange struct {
	ID                string                  `json:"id"`
	SessionID         string                  `json:"session_id"`
	ThreadID          string                  `json:"thread_id,omitempty"`
	Name              string                  `json:"name"`
	ExchangeType      string                  `json:"exchange_type,omitempty"`
	Classification    string                  `json:"classification,omitempty"`
	Resource          string                  `json:"resource,omitempty"`
	Summary           string                  `json:"summary,omitempty"`
	SentBy            string                  `json:"sent_by,omitempty"`
	Recipients        []string                `json:"recipients,omitempty"`
	IntegrityHash     string                  `json:"integrity_hash"`
	PolicyReceiptID   string                  `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string                  `json:"policy_receipt_hash,omitempty"`
	SealID            string                  `json:"seal_id,omitempty"`
	TraceLinkID       string                  `json:"trace_link_id,omitempty"`
	ChainOfCustody    []evidence.CustodyEntry `json:"chain_of_custody,omitempty"`
	CreatedAt         time.Time               `json:"created_at"`
	Metadata          map[string]string       `json:"metadata,omitempty"`
}

// SecureCellSharedOutput captures one policy-bound data exchange inside a
// session, including provenance-bearing custody details.
type SecureCellSharedOutput struct {
	ID                string                  `json:"id"`
	SessionID         string                  `json:"session_id"`
	Name              string                  `json:"name"`
	ArtifactType      string                  `json:"artifact_type,omitempty"`
	Classification    string                  `json:"classification,omitempty"`
	Resource          string                  `json:"resource,omitempty"`
	Summary           string                  `json:"summary,omitempty"`
	ProducedBy        string                  `json:"produced_by,omitempty"`
	SharedWith        []string                `json:"shared_with,omitempty"`
	IntegrityHash     string                  `json:"integrity_hash"`
	PolicyReceiptID   string                  `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string                  `json:"policy_receipt_hash,omitempty"`
	SealID            string                  `json:"seal_id,omitempty"`
	TraceLinkID       string                  `json:"trace_link_id,omitempty"`
	ChainOfCustody    []evidence.CustodyEntry `json:"chain_of_custody,omitempty"`
	CreatedAt         time.Time               `json:"created_at"`
	Metadata          map[string]string       `json:"metadata,omitempty"`
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
	Sessions          []SecureCellSession                    `json:"sessions,omitempty"`
	Threads           []SecureCellSessionThread              `json:"threads,omitempty"`
	SharedOutputs     []SecureCellSharedOutput               `json:"shared_outputs,omitempty"`
	SessionExchanges  []SecureCellSessionExchange            `json:"session_exchanges,omitempty"`
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
	SessionID               string                      `json:"session_id,omitempty"`
	ThreadID                string                      `json:"thread_id,omitempty"`
	SharedOutputID          string                      `json:"shared_output_id,omitempty"`
	SessionExchangeID       string                      `json:"session_exchange_id,omitempty"`
	SessionStatusBefore     SecureCellSessionStatus     `json:"session_status_before,omitempty"`
	SessionStatusAfter      SecureCellSessionStatus     `json:"session_status_after,omitempty"`
	ThreadStatusBefore      SecureCellThreadStatus      `json:"thread_status_before,omitempty"`
	ThreadStatusAfter       SecureCellThreadStatus      `json:"thread_status_after,omitempty"`
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

// SecureCellLifecycleEvent is the canonical event payload emitted after a
// secure-cell lifecycle mutation has been sealed and packaged successfully.
type SecureCellLifecycleEvent struct {
	EventID                     string                      `json:"event_id"`
	CellID                      string                      `json:"cell_id"`
	Name                        string                      `json:"name"`
	Purpose                     string                      `json:"purpose"`
	Jurisdiction                string                      `json:"jurisdiction,omitempty"`
	Action                      string                      `json:"action"`
	Actor                       string                      `json:"actor"`
	TargetType                  string                      `json:"target_type,omitempty"`
	TargetDID                   string                      `json:"target_did,omitempty"`
	SessionID                   string                      `json:"session_id,omitempty"`
	ThreadID                    string                      `json:"thread_id,omitempty"`
	SharedOutputID              string                      `json:"shared_output_id,omitempty"`
	SessionExchangeID           string                      `json:"session_exchange_id,omitempty"`
	SessionStatusBefore         SecureCellSessionStatus     `json:"session_status_before,omitempty"`
	SessionStatusAfter          SecureCellSessionStatus     `json:"session_status_after,omitempty"`
	ThreadStatusBefore          SecureCellThreadStatus      `json:"thread_status_before,omitempty"`
	ThreadStatusAfter           SecureCellThreadStatus      `json:"thread_status_after,omitempty"`
	CellStatus                  SecureCellStatus            `json:"cell_status"`
	CellStatusBefore            SecureCellStatus            `json:"cell_status_before,omitempty"`
	CellStatusAfter             SecureCellStatus            `json:"cell_status_after,omitempty"`
	ParticipantStatusBefore     SecureCellParticipantStatus `json:"participant_status_before,omitempty"`
	ParticipantStatusAfter      SecureCellParticipantStatus `json:"participant_status_after,omitempty"`
	TransitionID                string                      `json:"transition_id"`
	TransitionCount             int                         `json:"transition_count"`
	ParticipantCount            int                         `json:"participant_count"`
	SessionCount                int                         `json:"session_count"`
	ActiveSessionCount          int                         `json:"active_session_count"`
	ThreadCount                 int                         `json:"thread_count"`
	ActiveThreadCount           int                         `json:"active_thread_count"`
	SharedOutputCount           int                         `json:"shared_output_count"`
	SessionExchangeCount        int                         `json:"session_exchange_count"`
	ActiveParticipantCount      int                         `json:"active_participant_count"`
	QuarantinedParticipantCount int                         `json:"quarantined_participant_count"`
	RevokedParticipantCount     int                         `json:"revoked_participant_count"`
	PolicyReceiptID             string                      `json:"policy_receipt_id,omitempty"`
	PolicyReceiptContentHash    string                      `json:"policy_receipt_content_hash,omitempty"`
	ReceiptChainHash            string                      `json:"receipt_chain_hash,omitempty"`
	SealID                      string                      `json:"seal_id,omitempty"`
	ControlLedgerID             string                      `json:"control_ledger_id,omitempty"`
	ControlLedgerContentHash    string                      `json:"control_ledger_content_hash,omitempty"`
	PortablePackageHash         string                      `json:"portable_package_hash,omitempty"`
	PortablePackageSigned       bool                        `json:"portable_package_signed"`
	PortablePackageAnchored     bool                        `json:"portable_package_anchored"`
	Reason                      string                      `json:"reason,omitempty"`
	Metadata                    map[string]string           `json:"metadata,omitempty"`
	OccurredAt                  time.Time                   `json:"occurred_at"`
	PublishedAt                 time.Time                   `json:"published_at"`
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
	EventPublisher          SecureCellEventPublisher
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

	createReceipt, err := s.evaluateStage(ctx, normalized, "create", "", nil, normalized.OwnerIdentity.AgentID())
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

	outputID := secureCellSharedOutputID(run.request, *session, share.Name, actorDID, run.result.SharedOutputs)
	output := SecureCellSharedOutput{
		ID:             outputID,
		SessionID:      session.ID,
		Name:           firstNonEmpty(strings.TrimSpace(share.Name), fmt.Sprintf("%s Output %d", session.Name, len(session.SharedOutputIDs)+1)),
		ArtifactType:   firstNonEmpty(strings.TrimSpace(share.ArtifactType), "decision_packet"),
		Classification: classification,
		Resource:       firstNonEmpty(strings.TrimSpace(share.Resource), fmt.Sprintf("secure-cell:%s:session:%s:output:%s", run.result.CellID, session.ID, outputID)),
		Summary:        strings.TrimSpace(share.Summary),
		ProducedBy:     actorDID,
		SharedWith:     sharedWith,
		IntegrityHash:  secureCellResolveOutputIntegrityHash(share, outputID, session.ID, actorDID, sharedWith),
		CreatedAt:      time.Now().UTC(),
		Metadata:       cloneStringMap(share.Metadata),
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
		Metadata:            cloneStringMap(share.Metadata),
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

	exchangeID := secureCellSessionExchangeID(run.request, *session, exchange.Name, actorDID, run.result.SessionExchanges)
	item := SecureCellSessionExchange{
		ID:             exchangeID,
		SessionID:      session.ID,
		Name:           firstNonEmpty(strings.TrimSpace(exchange.Name), fmt.Sprintf("%s Exchange %d", session.Name, len(session.ExchangeIDs)+1)),
		ExchangeType:   firstNonEmpty(strings.TrimSpace(exchange.ExchangeType), "message"),
		Classification: classification,
		Resource:       firstNonEmpty(strings.TrimSpace(exchange.Resource), fmt.Sprintf("secure-cell:%s:session:%s:exchange:%s", run.result.CellID, session.ID, exchangeID)),
		Summary:        strings.TrimSpace(exchange.Summary),
		SentBy:         actorDID,
		Recipients:     recipients,
		IntegrityHash:  secureCellResolveExchangeIntegrityHash(exchange, exchangeID, session.ID, actorDID, recipients),
		CreatedAt:      time.Now().UTC(),
		Metadata:       cloneStringMap(exchange.Metadata),
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
		Metadata:            cloneStringMap(exchange.Metadata),
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

	exchangeID := secureCellThreadMessageID(run.request, *session, *thread, message.Name, actorDID, run.result.SessionExchanges)
	item := SecureCellSessionExchange{
		ID:             exchangeID,
		SessionID:      session.ID,
		ThreadID:       thread.ID,
		Name:           firstNonEmpty(strings.TrimSpace(message.Name), fmt.Sprintf("%s Message %d", thread.Name, len(thread.ExchangeIDs)+1)),
		ExchangeType:   firstNonEmpty(strings.TrimSpace(message.ExchangeType), "thread_message"),
		Classification: classification,
		Resource:       firstNonEmpty(strings.TrimSpace(message.Resource), fmt.Sprintf("secure-cell:%s:session:%s:thread:%s:message:%s", run.result.CellID, session.ID, thread.ID, exchangeID)),
		Summary:        strings.TrimSpace(message.Summary),
		SentBy:         actorDID,
		Recipients:     recipients,
		IntegrityHash:  secureCellResolveThreadMessageIntegrityHash(message, exchangeID, session.ID, thread.ID, actorDID, recipients),
		CreatedAt:      time.Now().UTC(),
		Metadata:       cloneStringMap(message.Metadata),
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
		Metadata:            cloneStringMap(message.Metadata),
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
	ledger.WithMetadata("sessions_total", fmt.Sprintf("%d", len(run.result.Sessions)))
	ledger.WithMetadata("sessions_active", fmt.Sprintf("%d", len(sessionsByStatus(run.result.Sessions, SecureCellSessionStatusActive))))
	ledger.WithMetadata("threads_total", fmt.Sprintf("%d", len(run.result.Threads)))
	ledger.WithMetadata("threads_active", fmt.Sprintf("%d", len(threadsByStatus(run.result.Threads, SecureCellThreadStatusActive))))
	ledger.WithMetadata("threads_quarantined", fmt.Sprintf("%d", len(threadsByStatus(run.result.Threads, SecureCellThreadStatusQuarantined))))
	ledger.WithMetadata("threads_closed", fmt.Sprintf("%d", len(threadsByStatus(run.result.Threads, SecureCellThreadStatusClosed))))
	ledger.WithMetadata("shared_outputs_total", fmt.Sprintf("%d", len(run.result.SharedOutputs)))
	ledger.WithMetadata("session_exchanges_total", fmt.Sprintf("%d", len(run.result.SessionExchanges)))
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
	sessionEvidenceRecordIDs := make([]string, 0, len(run.result.Sessions))
	threadEvidenceRecordIDs := make([]string, 0, len(run.result.Threads))
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
	admittedParticipants := make(map[string]struct{}, len(run.result.Transitions))
	sharedOutputTransitions := make(map[string]SecureCellTransition, len(run.result.SharedOutputs))

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
		if transition.ThreadID != "" {
			data["thread_id"] = transition.ThreadID
		}
		if transition.ThreadStatusBefore != "" {
			data["thread_status_before"] = string(transition.ThreadStatusBefore)
		}
		if transition.ThreadStatusAfter != "" {
			data["thread_status_after"] = string(transition.ThreadStatusAfter)
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
		if transition.Action == "secure_cell.session_started" || transition.Action == "secure_cell.session_closed" || transition.Action == "secure_cell.session_paused" || transition.Action == "secure_cell.session_resumed" || transition.Action == "secure_cell.session_quarantined" || transition.Action == "secure_cell.session_member_admitted" || transition.Action == "secure_cell.session_member_removed" {
			sessionLifecycleRecordIDs = append(sessionLifecycleRecordIDs, recordID)
		}
		if transition.Action == "secure_cell.session_thread_started" || transition.Action == "secure_cell.session_thread_closed" || transition.Action == "secure_cell.session_thread_resumed" || transition.Action == "secure_cell.session_thread_quarantined" {
			threadLifecycleRecordIDs = append(threadLifecycleRecordIDs, recordID)
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
	}

	for _, session := range run.result.Sessions {
		recordID := fmt.Sprintf("%s-session-%x", cellID(req), sha256.Sum256([]byte(session.ID)))
		sessionEvidenceRecordIDs = append(sessionEvidenceRecordIDs, recordID)
		sessionThreads := threadsForSession(run.result.Threads, session.ID)
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
		data := map[string]string{
			"thread_id":        thread.ID,
			"session_id":       thread.SessionID,
			"thread_name":      thread.Name,
			"thread_purpose":   thread.Purpose,
			"thread_status":    string(thread.Status),
			"participant_dids": strings.Join(thread.ParticipantDIDs, ","),
			"data_classes":     strings.Join(thread.DataClasses, ","),
			"started_by":       thread.StartedBy,
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

	for _, output := range run.result.SharedOutputs {
		recordID := fmt.Sprintf("%s-output-%x", cellID(req), sha256.Sum256([]byte(output.ID)))
		sharedOutputRecordIDs = append(sharedOutputRecordIDs, recordID)
		data := map[string]string{
			"shared_output_id":      output.ID,
			"session_id":            output.SessionID,
			"name":                  output.Name,
			"artifact_type":         output.ArtifactType,
			"classification":        output.Classification,
			"resource":              output.Resource,
			"integrity_hash":        output.IntegrityHash,
			"produced_by":           output.ProducedBy,
			"shared_with":           strings.Join(output.SharedWith, ","),
			"custody_entries_total": fmt.Sprintf("%d", len(output.ChainOfCustody)),
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
			"session_exchange_id":   item.ID,
			"session_id":            item.SessionID,
			"thread_id":             item.ThreadID,
			"name":                  item.Name,
			"exchange_type":         item.ExchangeType,
			"classification":        item.Classification,
			"resource":              item.Resource,
			"integrity_hash":        item.IntegrityHash,
			"sent_by":               item.SentBy,
			"recipients":            strings.Join(item.Recipients, ","),
			"custody_entries_total": fmt.Sprintf("%d", len(item.ChainOfCustody)),
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
		SharedOutputID:              transition.SharedOutputID,
		SessionExchangeID:           transition.SessionExchangeID,
		SessionStatusBefore:         transition.SessionStatusBefore,
		SessionStatusAfter:          transition.SessionStatusAfter,
		ThreadStatusBefore:          transition.ThreadStatusBefore,
		ThreadStatusAfter:           transition.ThreadStatusAfter,
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
	case "secure_cell.member_admitted":
		return "trust"
	case "secure_cell.session_started", "secure_cell.session_closed", "secure_cell.session_paused", "secure_cell.session_resumed", "secure_cell.session_member_admitted", "secure_cell.session_member_removed", "secure_cell.session_thread_started", "secure_cell.session_thread_closed", "secure_cell.session_thread_resumed":
		return "collaboration"
	case "secure_cell.session_shared", "secure_cell.session_exchange", "secure_cell.session_thread_message":
		return "exchange"
	case "secure_cell.member_quarantined", "secure_cell.member_revoked", "secure_cell.member_released", "secure_cell.quarantine_expired", "secure_cell.session_quarantined", "secure_cell.session_thread_quarantined":
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
	case "secure_cell.session_started":
		return "start_session"
	case "secure_cell.session_thread_started":
		return "start_session_thread"
	case "secure_cell.session_thread_message":
		return "message_session_thread"
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

func secureCellSessionHasParticipant(session SecureCellSession, participantDID string) bool {
	for _, did := range session.ParticipantDIDs {
		if strings.TrimSpace(did) == strings.TrimSpace(participantDID) {
			return true
		}
	}
	return false
}

func secureCellThreadHasParticipant(thread SecureCellSessionThread, participantDID string) bool {
	for _, did := range thread.ParticipantDIDs {
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
				secureCellSessionStartAction,
				secureCellSessionThreadStartAction,
				secureCellSessionThreadMessageAction,
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
	case "start_session":
		return secureCellSessionStartAction
	case "start_session_thread":
		return secureCellSessionThreadStartAction
	case "message_session_thread":
		return secureCellSessionThreadMessageAction
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
