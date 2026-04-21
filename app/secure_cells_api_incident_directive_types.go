package app

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
	securecellsintegration "github.com/aethelred/aethelred/pkg/integrations/securecells"
)

type secureCellFederationIncidentDirectiveCreateRequest struct {
	ActorIdentity       json.RawMessage                                                      `json:"actor_identity,omitempty"`
	PolicyReceipt       *policy.SignedPolicyReceipt                                          `json:"policy_receipt,omitempty"`
	DirectiveType       string                                                               `json:"directive_type,omitempty"`
	Title               string                                                               `json:"title,omitempty"`
	Summary             string                                                               `json:"summary,omitempty"`
	Description         string                                                               `json:"description,omitempty"`
	Priority            securecellsintegration.SecureCellFederationIncidentDirectivePriority `json:"priority,omitempty"`
	AssigneeParty       securecellsintegration.SecureCellFederationIncidentResponseParty     `json:"assignee_party,omitempty"`
	ReviewerParty       securecellsintegration.SecureCellFederationIncidentResponseParty     `json:"reviewer_party,omitempty"`
	AssigneeDID         string                                                               `json:"assignee_did,omitempty"`
	ReviewerDID         string                                                               `json:"reviewer_did,omitempty"`
	RelatedReportIDs    []string                                                             `json:"related_report_ids,omitempty"`
	RelatedAmendmentIDs []string                                                             `json:"related_amendment_ids,omitempty"`
	EvidenceIDs         []string                                                             `json:"evidence_ids,omitempty"`
	DueAt               *time.Time                                                           `json:"due_at,omitempty"`
	Reason              string                                                               `json:"reason,omitempty"`
	Metadata            map[string]string                                                    `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveAcknowledgeRequest struct {
	ActorIdentity      json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt      *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	AcknowledgingParty securecellsintegration.SecureCellFederationIncidentResponseParty `json:"acknowledging_party,omitempty"`
	Reason             string                                                           `json:"reason,omitempty"`
	Metadata           map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveCompleteRequest struct {
	ActorIdentity         json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt         *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	CompletingParty       securecellsintegration.SecureCellFederationIncidentResponseParty `json:"completing_party,omitempty"`
	CompletionSummary     string                                                           `json:"completion_summary,omitempty"`
	CompletionDescription string                                                           `json:"completion_description,omitempty"`
	EvidenceIDs           []string                                                         `json:"evidence_ids,omitempty"`
	Reason                string                                                           `json:"reason,omitempty"`
	Metadata              map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveVerifyRequest struct {
	ActorIdentity           json.RawMessage                                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt           *policy.SignedPolicyReceipt                                                      `json:"policy_receipt,omitempty"`
	ReviewingParty          securecellsintegration.SecureCellFederationIncidentResponseParty                 `json:"reviewing_party,omitempty"`
	Decision                securecellsintegration.SecureCellFederationIncidentDirectiveVerificationDecision `json:"decision,omitempty"`
	VerificationSummary     string                                                                           `json:"verification_summary,omitempty"`
	VerificationDescription string                                                                           `json:"verification_description,omitempty"`
	EvidenceIDs             []string                                                                         `json:"evidence_ids,omitempty"`
	Reason                  string                                                                           `json:"reason,omitempty"`
	Metadata                map[string]string                                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionRequest struct {
	ActorIdentity              json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt              *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	RequestingParty            securecellsintegration.SecureCellFederationIncidentResponseParty `json:"requesting_party,omitempty"`
	Summary                    string                                                           `json:"summary,omitempty"`
	Description                string                                                           `json:"description,omitempty"`
	EvidenceIDs                []string                                                         `json:"evidence_ids,omitempty"`
	ProposedDueAt              *time.Time                                                       `json:"proposed_due_at,omitempty"`
	ReviewApprovalThreshold    int                                                              `json:"review_approval_threshold,omitempty"`
	EligibleReviewerDIDs       []string                                                         `json:"eligible_reviewer_dids,omitempty"`
	DisputeResolutionThreshold int                                                              `json:"dispute_resolution_threshold,omitempty"`
	EligibleResolverDIDs       []string                                                         `json:"eligible_resolver_dids,omitempty"`
	Reason                     string                                                           `json:"reason,omitempty"`
	Metadata                   map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionApproveRequest struct {
	ActorIdentity       json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt       *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	ReviewingParty      securecellsintegration.SecureCellFederationIncidentResponseParty `json:"reviewing_party,omitempty"`
	DecisionSummary     string                                                           `json:"decision_summary,omitempty"`
	DecisionDescription string                                                           `json:"decision_description,omitempty"`
	EvidenceIDs         []string                                                         `json:"evidence_ids,omitempty"`
	Reason              string                                                           `json:"reason,omitempty"`
	Metadata            map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionRejectRequest struct {
	ActorIdentity       json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt       *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	ReviewingParty      securecellsintegration.SecureCellFederationIncidentResponseParty `json:"reviewing_party,omitempty"`
	DecisionSummary     string                                                           `json:"decision_summary,omitempty"`
	DecisionDescription string                                                           `json:"decision_description,omitempty"`
	EvidenceIDs         []string                                                         `json:"evidence_ids,omitempty"`
	Reason              string                                                           `json:"reason,omitempty"`
	Metadata            map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionDisputeRequest struct {
	ActorIdentity    json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt    *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	ChallengingParty securecellsintegration.SecureCellFederationIncidentResponseParty `json:"challenging_party,omitempty"`
	Summary          string                                                           `json:"summary,omitempty"`
	Description      string                                                           `json:"description,omitempty"`
	EvidenceIDs      []string                                                         `json:"evidence_ids,omitempty"`
	Reason           string                                                           `json:"reason,omitempty"`
	Metadata         map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionDisputeResolveRequest struct {
	ActorIdentity         json.RawMessage                                                                        `json:"actor_identity,omitempty"`
	PolicyReceipt         *policy.SignedPolicyReceipt                                                            `json:"policy_receipt,omitempty"`
	RespondingParty       securecellsintegration.SecureCellFederationIncidentResponseParty                       `json:"responding_party,omitempty"`
	Resolution            securecellsintegration.SecureCellFederationIncidentDirectiveExtensionDisputeResolution `json:"resolution,omitempty"`
	ResolutionSummary     string                                                                                 `json:"resolution_summary,omitempty"`
	ResolutionDescription string                                                                                 `json:"resolution_description,omitempty"`
	EvidenceIDs           []string                                                                               `json:"evidence_ids,omitempty"`
	Reason                string                                                                                 `json:"reason,omitempty"`
	Metadata              map[string]string                                                                      `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionDelegationRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	TargetDID     string                      `json:"target_did,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealRequest struct {
	ActorIdentity             json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt             *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	AppealingParty            securecellsintegration.SecureCellFederationIncidentResponseParty `json:"appealing_party,omitempty"`
	Summary                   string                                                           `json:"summary,omitempty"`
	Description               string                                                           `json:"description,omitempty"`
	EvidenceIDs               []string                                                         `json:"evidence_ids,omitempty"`
	BoardReviewThreshold      int                                                              `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs []string                                                         `json:"eligible_board_reviewer_dids,omitempty"`
	Reason                    string                                                           `json:"reason,omitempty"`
	Metadata                  map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealRulingRequest struct {
	ActorIdentity     json.RawMessage                                                                   `json:"actor_identity,omitempty"`
	PolicyReceipt     *policy.SignedPolicyReceipt                                                       `json:"policy_receipt,omitempty"`
	BoardParty        securecellsintegration.SecureCellFederationIncidentResponseParty                  `json:"board_party,omitempty"`
	Ruling            securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealRuling `json:"ruling,omitempty"`
	RulingSummary     string                                                                            `json:"ruling_summary,omitempty"`
	RulingDescription string                                                                            `json:"ruling_description,omitempty"`
	EvidenceIDs       []string                                                                          `json:"evidence_ids,omitempty"`
	Reason            string                                                                            `json:"reason,omitempty"`
	Metadata          map[string]string                                                                 `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealRecuseRequest struct {
	ActorIdentity json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	BoardParty    securecellsintegration.SecureCellFederationIncidentResponseParty `json:"board_party,omitempty"`
	Summary       string                                                           `json:"summary,omitempty"`
	Description   string                                                           `json:"description,omitempty"`
	EvidenceIDs   []string                                                         `json:"evidence_ids,omitempty"`
	Reason        string                                                           `json:"reason,omitempty"`
	Metadata      map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealRehearingRequest struct {
	ActorIdentity             json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt             *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	AppealingParty            securecellsintegration.SecureCellFederationIncidentResponseParty `json:"appealing_party,omitempty"`
	Summary                   string                                                           `json:"summary,omitempty"`
	Description               string                                                           `json:"description,omitempty"`
	EvidenceIDs               []string                                                         `json:"evidence_ids,omitempty"`
	BoardReviewThreshold      int                                                              `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs []string                                                         `json:"eligible_board_reviewer_dids,omitempty"`
	Reason                    string                                                           `json:"reason,omitempty"`
	Metadata                  map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealAcknowledgeRequest struct {
	ActorIdentity      json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt      *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	AcknowledgingParty securecellsintegration.SecureCellFederationIncidentResponseParty `json:"acknowledging_party,omitempty"`
	Summary            string                                                           `json:"summary,omitempty"`
	Description        string                                                           `json:"description,omitempty"`
	EvidenceIDs        []string                                                         `json:"evidence_ids,omitempty"`
	Reason             string                                                           `json:"reason,omitempty"`
	Metadata           map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationAcknowledgeRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationDisputeRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	Divergences   []string                    `json:"divergences,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolveRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRequest struct {
	ActorIdentity             json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt             *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	ChallengingParty          securecellsintegration.SecureCellFederationIncidentResponseParty `json:"challenging_party,omitempty"`
	Summary                   string                                                           `json:"summary,omitempty"`
	Description               string                                                           `json:"description,omitempty"`
	EvidenceIDs               []string                                                         `json:"evidence_ids,omitempty"`
	BoardReviewThreshold      int                                                              `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs []string                                                         `json:"eligible_board_reviewer_dids,omitempty"`
	Reason                    string                                                           `json:"reason,omitempty"`
	Metadata                  map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRulingRequest struct {
	ActorIdentity     json.RawMessage                                                                   `json:"actor_identity,omitempty"`
	PolicyReceipt     *policy.SignedPolicyReceipt                                                       `json:"policy_receipt,omitempty"`
	BoardParty        securecellsintegration.SecureCellFederationIncidentResponseParty                  `json:"board_party,omitempty"`
	Ruling            securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealRuling `json:"ruling,omitempty"`
	RulingSummary     string                                                                            `json:"ruling_summary,omitempty"`
	RulingDescription string                                                                            `json:"ruling_description,omitempty"`
	EvidenceIDs       []string                                                                          `json:"evidence_ids,omitempty"`
	Reason            string                                                                            `json:"reason,omitempty"`
	Metadata          map[string]string                                                                 `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRequest struct {
	ActorIdentity             json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt             *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	AppealingParty            securecellsintegration.SecureCellFederationIncidentResponseParty `json:"appealing_party,omitempty"`
	Summary                   string                                                           `json:"summary,omitempty"`
	Description               string                                                           `json:"description,omitempty"`
	EvidenceIDs               []string                                                         `json:"evidence_ids,omitempty"`
	BoardReviewThreshold      int                                                              `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs []string                                                         `json:"eligible_board_reviewer_dids,omitempty"`
	Reason                    string                                                           `json:"reason,omitempty"`
	Metadata                  map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRulingRequest struct {
	ActorIdentity     json.RawMessage                                                                   `json:"actor_identity,omitempty"`
	PolicyReceipt     *policy.SignedPolicyReceipt                                                       `json:"policy_receipt,omitempty"`
	BoardParty        securecellsintegration.SecureCellFederationIncidentResponseParty                  `json:"board_party,omitempty"`
	Ruling            securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealRuling `json:"ruling,omitempty"`
	RulingSummary     string                                                                            `json:"ruling_summary,omitempty"`
	RulingDescription string                                                                            `json:"ruling_description,omitempty"`
	EvidenceIDs       []string                                                                          `json:"evidence_ids,omitempty"`
	Reason            string                                                                            `json:"reason,omitempty"`
	Metadata          map[string]string                                                                 `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuseRequest struct {
	ActorIdentity json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	BoardParty    securecellsintegration.SecureCellFederationIncidentResponseParty `json:"board_party,omitempty"`
	Summary       string                                                           `json:"summary,omitempty"`
	Description   string                                                           `json:"description,omitempty"`
	EvidenceIDs   []string                                                         `json:"evidence_ids,omitempty"`
	Reason        string                                                           `json:"reason,omitempty"`
	Metadata      map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehearingRequest struct {
	ActorIdentity             json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt             *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	AppealingParty            securecellsintegration.SecureCellFederationIncidentResponseParty `json:"appealing_party,omitempty"`
	Summary                   string                                                           `json:"summary,omitempty"`
	Description               string                                                           `json:"description,omitempty"`
	EvidenceIDs               []string                                                         `json:"evidence_ids,omitempty"`
	BoardReviewThreshold      int                                                              `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs []string                                                         `json:"eligible_board_reviewer_dids,omitempty"`
	Reason                    string                                                           `json:"reason,omitempty"`
	Metadata                  map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgeRequest struct {
	ActorIdentity      json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt      *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	AcknowledgingParty securecellsintegration.SecureCellFederationIncidentResponseParty `json:"acknowledging_party,omitempty"`
	Summary            string                                                           `json:"summary,omitempty"`
	Description        string                                                           `json:"description,omitempty"`
	EvidenceIDs        []string                                                         `json:"evidence_ids,omitempty"`
	Reason             string                                                           `json:"reason,omitempty"`
	Metadata           map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeRequest struct {
	ActorIdentity         json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt         *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	CounterpartyReference string                      `json:"counterparty_reference,omitempty"`
	Reason                string                      `json:"reason,omitempty"`
	Metadata              map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttestationRequest struct {
	ActorIdentity          json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt          *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	CounterpartySnapshotID string                      `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyReference  string                      `json:"counterparty_reference,omitempty"`
	Reason                 string                      `json:"reason,omitempty"`
	Metadata               map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttestationRequest struct {
	ActorIdentity         json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt         *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	CounterpartyReference string                      `json:"counterparty_reference,omitempty"`
	Reason                string                      `json:"reason,omitempty"`
	Metadata              map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveSummary `json:"items"`
}

type secureCellOverdueFederationIncidentDirectiveListResponse struct {
	Items []securecellsintegration.SecureCellOverdueFederationIncidentDirective `json:"items"`
}

type secureCellFederationIncidentDirectiveActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveActionRecord `json:"items"`
}

type secureCellFederationIncidentDirectiveAutomationActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveAutomationActionRecord `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionSummary `json:"items"`
}

type secureCellOverdueFederationIncidentDirectiveExtensionListResponse struct {
	Items []securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtension `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionDisputeListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionDisputeSummary `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAutomationActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAutomationActionRecord `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealSummary `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealRecusalListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealRecusalSummary `json:"items"`
}

type secureCellFederationCounterpartyIncidentDirectiveExtensionAppealListResponse struct {
	Items []securecellsintegration.SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummary `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary `json:"items"`
}

type secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealListResponse struct {
	Items []securecellsintegration.SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalSummary `json:"items"`
}

type secureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealListResponse struct {
	Items []securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionRecord `json:"items"`
}

type secureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeListResponse struct {
	Items []securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallenge `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionRecord `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord `json:"items"`
}

type secureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationListResponse struct {
	Items []securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliation `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionRecord `json:"items"`
}

type secureCellOverdueFederationIncidentDirectiveExtensionAppealListResponse struct {
	Items []securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppeal `json:"items"`
}

type secureCellFederationIncidentDirectiveExtensionAppealAutomationActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionRecord `json:"items"`
}

type secureCellFederationIncidentDirectiveQueryResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentDirective `json:"result,omitempty"`
}

func parseSecureCellFederationIncidentDirectiveFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		AssigneeParty:  securecellsintegration.SecureCellFederationIncidentResponseParty(strings.TrimSpace(r.URL.Query().Get("assignee_party"))),
		ReviewerParty:  securecellsintegration.SecureCellFederationIncidentResponseParty(strings.TrimSpace(r.URL.Query().Get("reviewer_party"))),
		Status:         securecellsintegration.SecureCellFederationIncidentDirectiveStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
		Priority:       securecellsintegration.SecureCellFederationIncidentDirectivePriority(strings.TrimSpace(r.URL.Query().Get("priority"))),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellOverdueFederationIncidentDirectiveFilter(r *http.Request) (securecellsintegration.SecureCellOverdueFederationIncidentDirectiveFilter, error) {
	filter := securecellsintegration.SecureCellOverdueFederationIncidentDirectiveFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("before")); raw != "" {
		before, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Before = &before
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveActionFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveActionFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		Action:         strings.TrimSpace(r.URL.Query().Get("action")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveAutomationActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveAutomationActionFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveAutomationActionFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ContractID:     strings.TrimSpace(r.URL.Query().Get("contract_id")),
		Action:         strings.TrimSpace(r.URL.Query().Get("action")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:    strings.TrimSpace(r.URL.Query().Get("extension_id")),
		Status:         securecellsintegration.SecureCellFederationIncidentDirectiveExtensionStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellOverdueFederationIncidentDirectiveExtensionFilter(r *http.Request) (securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionFilter, error) {
	filter := securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:    strings.TrimSpace(r.URL.Query().Get("extension_id")),
		Status:         securecellsintegration.SecureCellFederationIncidentDirectiveExtensionStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("before")); raw != "" {
		before, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Before = &before
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionDisputeFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionDisputeFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionDisputeFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:    strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:      strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		Status:         securecellsintegration.SecureCellFederationIncidentDirectiveExtensionDisputeStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAutomationActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAutomationActionFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAutomationActionFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:    strings.TrimSpace(r.URL.Query().Get("extension_id")),
		ContractID:     strings.TrimSpace(r.URL.Query().Get("contract_id")),
		Action:         strings.TrimSpace(r.URL.Query().Get("action")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:    strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:      strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:       strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ParentAppealID: strings.TrimSpace(r.URL.Query().Get("parent_appeal_id")),
		Status:         securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealFilter(r *http.Request) (securecellsintegration.SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealFilter, error) {
	filter := securecellsintegration.SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealFilter{
		CellID:               strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID:       strings.TrimSpace(r.URL.Query().Get("organization_id")),
		ContractID:           strings.TrimSpace(r.URL.Query().Get("contract_id")),
		IncidentID:           strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:           strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:          strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:          strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:            strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:             strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		Status:               securecellsintegration.SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
		ReconciliationStatus: securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus(strings.TrimSpace(r.URL.Query().Get("reconciliation_status"))),
		Signer:               strings.TrimSpace(r.URL.Query().Get("signer")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:    strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:      strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:       strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:  strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		Status:         securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
		ReviewStatus:   securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus(strings.TrimSpace(r.URL.Query().Get("review_status"))),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:    strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:      strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:       strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:  strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		Action:         securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionType(strings.TrimSpace(r.URL.Query().Get("action"))),
		ReviewStatus:   securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus(strings.TrimSpace(r.URL.Query().Get("review_status"))),
		ActorDID:       strings.TrimSpace(r.URL.Query().Get("actor_did")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter{
		CellID:           strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID:   strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:       strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:       strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:      strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:      strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:        strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:         strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:    strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		ChallengeID:      strings.TrimSpace(r.URL.Query().Get("challenge_id")),
		Status:           securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
		ChallengingParty: securecellsintegration.SecureCellFederationIncidentResponseParty(strings.TrimSpace(r.URL.Query().Get("challenging_party"))),
		BoardParty:       securecellsintegration.SecureCellFederationIncidentResponseParty(strings.TrimSpace(r.URL.Query().Get("board_party"))),
		Ruling:           securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(r.URL.Query().Get("ruling"))),
		ActorDID:         strings.TrimSpace(r.URL.Query().Get("actor_did")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFilter{
		CellID:           strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID:   strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:       strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:       strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:      strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:      strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:        strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:         strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:    strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		ChallengeID:      strings.TrimSpace(r.URL.Query().Get("challenge_id")),
		Status:           securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
		Action:           securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionType(strings.TrimSpace(r.URL.Query().Get("action"))),
		ChallengingParty: securecellsintegration.SecureCellFederationIncidentResponseParty(strings.TrimSpace(r.URL.Query().Get("challenging_party"))),
		BoardParty:       securecellsintegration.SecureCellFederationIncidentResponseParty(strings.TrimSpace(r.URL.Query().Get("board_party"))),
		Ruling:           securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(r.URL.Query().Get("ruling"))),
		ActorDID:         strings.TrimSpace(r.URL.Query().Get("actor_did")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter{
		CellID:                  strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID:          strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:              strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:              strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:             strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:             strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:               strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:                strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:           strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		ChallengeID:             strings.TrimSpace(r.URL.Query().Get("challenge_id")),
		ChallengeAppealID:       strings.TrimSpace(r.URL.Query().Get("challenge_appeal_id")),
		ParentChallengeAppealID: strings.TrimSpace(r.URL.Query().Get("parent_challenge_appeal_id")),
		Status:                  securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter(r *http.Request) (securecellsintegration.SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter, error) {
	filter := securecellsintegration.SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter{
		CellID:                  strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID:          strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:              strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:              strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:             strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:             strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:               strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:                strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:           strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		ChallengeID:             strings.TrimSpace(r.URL.Query().Get("challenge_id")),
		ChallengeAppealID:       strings.TrimSpace(r.URL.Query().Get("challenge_appeal_id")),
		ParentChallengeAppealID: strings.TrimSpace(r.URL.Query().Get("parent_challenge_appeal_id")),
		Status:                  securecellsintegration.SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
		AlignmentStatus:         securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus(strings.TrimSpace(r.URL.Query().Get("alignment_status"))),
		Signer:                  strings.TrimSpace(r.URL.Query().Get("signer")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter{
		CellID:            strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID:    strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:        strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:        strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:       strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:       strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:         strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:          strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:     strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		ChallengeID:       strings.TrimSpace(r.URL.Query().Get("challenge_id")),
		ChallengeAppealID: strings.TrimSpace(r.URL.Query().Get("challenge_appeal_id")),
		Status:            securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
		Action:            securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionType(strings.TrimSpace(r.URL.Query().Get("action"))),
		ActorDID:          strings.TrimSpace(r.URL.Query().Get("actor_did")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalFilter{
		CellID:                  strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID:          strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:              strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:              strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:             strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:             strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:               strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:                strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:           strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		ChallengeID:             strings.TrimSpace(r.URL.Query().Get("challenge_id")),
		ChallengeAppealID:       strings.TrimSpace(r.URL.Query().Get("challenge_appeal_id")),
		ParentChallengeAppealID: strings.TrimSpace(r.URL.Query().Get("parent_challenge_appeal_id")),
		ActorDID:                strings.TrimSpace(r.URL.Query().Get("actor_did")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter(r *http.Request) (securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter, error) {
	filter := securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter{
		CellID:            strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID:    strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:        strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:        strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:       strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:       strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:         strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:          strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:     strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		ChallengeID:       strings.TrimSpace(r.URL.Query().Get("challenge_id")),
		ChallengeAppealID: strings.TrimSpace(r.URL.Query().Get("challenge_appeal_id")),
		Status:            securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("before")); raw != "" {
		before, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Before = &before
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionFilter{
		CellID:            strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID:    strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:        strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:        strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:       strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:       strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:         strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:          strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:     strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		ChallengeID:       strings.TrimSpace(r.URL.Query().Get("challenge_id")),
		ChallengeAppealID: strings.TrimSpace(r.URL.Query().Get("challenge_appeal_id")),
		ContractID:        strings.TrimSpace(r.URL.Query().Get("contract_id")),
		Action:            strings.TrimSpace(r.URL.Query().Get("action")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFilter{
		CellID:            strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID:    strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:        strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:        strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:       strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:       strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:         strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:          strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:     strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		Attestation:       securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationType(strings.TrimSpace(r.URL.Query().Get("attestation"))),
		AttestationStatus: securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus(strings.TrimSpace(r.URL.Query().Get("attestation_status"))),
		ActorDID:          strings.TrimSpace(r.URL.Query().Get("actor_did")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealRecusalFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealRecusalFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealRecusalFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:    strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:      strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:       strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ActorDID:       strings.TrimSpace(r.URL.Query().Get("actor_did")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationFilter(r *http.Request) (securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationFilter, error) {
	filter := securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationFilter{
		CellID:            strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID:    strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:        strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:        strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:       strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:       strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:         strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:          strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:     strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		Status:            securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
		ReviewStatus:      securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus(strings.TrimSpace(r.URL.Query().Get("review_status"))),
		AttestationStatus: securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus(strings.TrimSpace(r.URL.Query().Get("attestation_status"))),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("before")); raw != "" {
		before, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Before = &before
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:    strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:      strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:       strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:  strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		ContractID:     strings.TrimSpace(r.URL.Query().Get("contract_id")),
		Action:         strings.TrimSpace(r.URL.Query().Get("action")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter(r *http.Request) (securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter, error) {
	filter := securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter{
		CellID:           strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID:   strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:       strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:       strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:      strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:      strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:        strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:         strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:    strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		ChallengeID:      strings.TrimSpace(r.URL.Query().Get("challenge_id")),
		Status:           securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
		ChallengingParty: securecellsintegration.SecureCellFederationIncidentResponseParty(strings.TrimSpace(r.URL.Query().Get("challenging_party"))),
		BoardParty:       securecellsintegration.SecureCellFederationIncidentResponseParty(strings.TrimSpace(r.URL.Query().Get("board_party"))),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("before")); raw != "" {
		before, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Before = &before
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:    strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:      strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:       strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ComparisonKey:  strings.TrimSpace(r.URL.Query().Get("comparison_key")),
		ChallengeID:    strings.TrimSpace(r.URL.Query().Get("challenge_id")),
		ContractID:     strings.TrimSpace(r.URL.Query().Get("contract_id")),
		Action:         strings.TrimSpace(r.URL.Query().Get("action")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealFilter(r *http.Request) (securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealFilter, error) {
	filter := securecellsintegration.SecureCellOverdueFederationIncidentDirectiveExtensionAppealFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:    strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:      strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:       strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		Status:         securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("before")); raw != "" {
		before, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Before = &before
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealAutomationActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionFilter, error) {
	filter := securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionFilter{
		CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
		OrganizationID: strings.TrimSpace(r.URL.Query().Get("organization_id")),
		IncidentID:     strings.TrimSpace(r.URL.Query().Get("incident_id")),
		ResponseID:     strings.TrimSpace(r.URL.Query().Get("response_id")),
		DirectiveID:    strings.TrimSpace(r.URL.Query().Get("directive_id")),
		ExtensionID:    strings.TrimSpace(r.URL.Query().Get("extension_id")),
		DisputeID:      strings.TrimSpace(r.URL.Query().Get("dispute_id")),
		AppealID:       strings.TrimSpace(r.URL.Query().Get("appeal_id")),
		ContractID:     strings.TrimSpace(r.URL.Query().Get("contract_id")),
		Action:         strings.TrimSpace(r.URL.Query().Get("action")),
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			return filter, err
		}
		filter.Limit = limit
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		since, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("until")); raw != "" {
		until, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func parseSecureCellFederationIncidentDirectiveActionPath(path, suffix string) (string, string, error) {
	path = strings.TrimSpace(path)
	suffix = strings.TrimSpace(suffix)
	trimmed := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(trimmed, suffix) {
			return "", "", http.ErrNotSupported
		}
		trimmed = strings.TrimSuffix(trimmed, suffix)
	}
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-directives" {
		return "", "", http.ErrNotSupported
	}
	return parts[0], parts[3], nil
}

func parseSecureCellFederationIncidentDirectiveExtensionActionPath(path, suffix string) (string, string, error) {
	path = strings.TrimSpace(path)
	suffix = strings.TrimSpace(suffix)
	trimmed := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(trimmed, suffix) {
			return "", "", http.ErrNotSupported
		}
		trimmed = strings.TrimSuffix(trimmed, suffix)
	}
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-directive-extensions" {
		return "", "", http.ErrNotSupported
	}
	return parts[0], parts[3], nil
}

func parseSecureCellFederationIncidentDirectiveExtensionDisputeActionPath(path, suffix string) (string, string, error) {
	path = strings.TrimSpace(path)
	suffix = strings.TrimSpace(suffix)
	trimmed := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(trimmed, suffix) {
			return "", "", http.ErrNotSupported
		}
		trimmed = strings.TrimSuffix(trimmed, suffix)
	}
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-directive-extension-disputes" {
		return "", "", http.ErrNotSupported
	}
	return parts[0], parts[3], nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealActionPath(path, suffix string) (string, string, error) {
	path = strings.TrimSpace(path)
	suffix = strings.TrimSpace(suffix)
	trimmed := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(trimmed, suffix) {
			return "", "", http.ErrNotSupported
		}
		trimmed = strings.TrimSuffix(trimmed, suffix)
	}
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-directive-extension-appeals" {
		return "", "", http.ErrNotSupported
	}
	return parts[0], parts[3], nil
}
