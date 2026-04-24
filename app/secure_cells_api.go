package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cosmos/cosmos-sdk/client/flags"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	cosmossdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/spf13/cast"

	"github.com/aethelred/aethelred/pkg/audit"
	"github.com/aethelred/aethelred/pkg/confidential"
	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/aethelred/aethelred/pkg/governance/policy"
	securecellsintegration "github.com/aethelred/aethelred/pkg/integrations/securecells"
	sealsdk "github.com/aethelred/aethelred/pkg/seal/sdk"
	pouwtypes "github.com/aethelred/aethelred/x/pouw/types"
	sealtypes "github.com/aethelred/aethelred/x/seal/types"
)

const (
	secureCellsCollectionRoute = "/api/v1/secure-cells"
	secureCellsItemPrefix      = "/api/v1/secure-cells/"
)

type secureCellAPIErrorResponse struct {
	Error string `json:"error"`
}

type secureCellCreateRequest struct {
	Identity      json.RawMessage                                `json:"identity"`
	PolicyReceipt *policy.SignedPolicyReceipt                    `json:"policy_receipt,omitempty"`
	Name          string                                         `json:"name"`
	Purpose       string                                         `json:"purpose"`
	Resource      string                                         `json:"resource,omitempty"`
	Jurisdiction  string                                         `json:"jurisdiction,omitempty"`
	Participants  []securecellsintegration.SecureCellParticipant `json:"participants,omitempty"`
	Policy        securecellsintegration.SecureCellPolicy        `json:"policy"`
	Metadata      map[string]string                              `json:"metadata,omitempty"`
}

type secureCellAdmitMemberRequest struct {
	ActorIdentity json.RawMessage                              `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt                  `json:"policy_receipt,omitempty"`
	Participant   securecellsintegration.SecureCellParticipant `json:"participant"`
	Reason        string                                       `json:"reason,omitempty"`
	Metadata      map[string]string                            `json:"metadata,omitempty"`
}

type secureCellFederationInviteRequest struct {
	ActorIdentity                       json.RawMessage                                             `json:"actor_identity,omitempty"`
	PolicyReceipt                       *policy.SignedPolicyReceipt                                 `json:"policy_receipt,omitempty"`
	SponsorOfRecord                     string                                                      `json:"sponsor_of_record,omitempty"`
	OrganizationName                    string                                                      `json:"organization_name,omitempty"`
	Jurisdiction                        string                                                      `json:"jurisdiction,omitempty"`
	ExpectedDID                         string                                                      `json:"expected_did,omitempty"`
	Role                                string                                                      `json:"role,omitempty"`
	SessionScopeIDs                     []string                                                    `json:"session_scope_ids,omitempty"`
	DataClasses                         []string                                                    `json:"data_classes,omitempty"`
	ComputeZones                        []string                                                    `json:"compute_zones,omitempty"`
	AllowedActions                      []string                                                    `json:"allowed_actions,omitempty"`
	CounterproposalGovernanceTemplate   string                                                      `json:"counterproposal_governance_template,omitempty"`
	CounterproposalApprovalThreshold    *int                                                        `json:"counterproposal_approval_threshold,omitempty"`
	CounterproposalEligibleApproverDIDs []string                                                    `json:"counterproposal_eligible_approver_dids,omitempty"`
	CounterproposalEscalationLadder     []securecellsintegration.SecureCellFederationEscalationTier `json:"counterproposal_escalation_ladder,omitempty"`
	CounterproposalResolutionDueAt      *time.Time                                                  `json:"counterproposal_resolution_due_at,omitempty"`
	CounterproposalAutoSuspendOnOverdue *bool                                                       `json:"counterproposal_auto_suspend_on_overdue,omitempty"`
	Resource                            string                                                      `json:"resource,omitempty"`
	Reason                              string                                                      `json:"reason,omitempty"`
	Metadata                            map[string]string                                           `json:"metadata,omitempty"`
}

type secureCellFederationAcceptRequest struct {
	ActorIdentity          json.RawMessage                              `json:"actor_identity,omitempty"`
	PolicyReceipt          *policy.SignedPolicyReceipt                  `json:"policy_receipt,omitempty"`
	InvitationID           string                                       `json:"invitation_id,omitempty"`
	Participant            securecellsintegration.SecureCellParticipant `json:"participant"`
	OfferedSessionScopeIDs []string                                     `json:"offered_session_scope_ids,omitempty"`
	OfferedDataClasses     []string                                     `json:"offered_data_classes,omitempty"`
	OfferedComputeZones    []string                                     `json:"offered_compute_zones,omitempty"`
	OfferedActions         []string                                     `json:"offered_actions,omitempty"`
	Reason                 string                                       `json:"reason,omitempty"`
	Metadata               map[string]string                            `json:"metadata,omitempty"`
}

type secureCellFederationCounterproposalRequest struct {
	ActorIdentity          json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt          *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	OfferedSessionScopeIDs []string                    `json:"offered_session_scope_ids,omitempty"`
	OfferedDataClasses     []string                    `json:"offered_data_classes,omitempty"`
	OfferedComputeZones    []string                    `json:"offered_compute_zones,omitempty"`
	OfferedActions         []string                    `json:"offered_actions,omitempty"`
	Resource               string                      `json:"resource,omitempty"`
	Reason                 string                      `json:"reason,omitempty"`
	Metadata               map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationContractRenewRequest struct {
	ActorIdentity          json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt          *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	SessionScopeIDs        []string                    `json:"session_scope_ids,omitempty"`
	DataClasses            []string                    `json:"data_classes,omitempty"`
	ComputeZones           []string                    `json:"compute_zones,omitempty"`
	AllowedActions         []string                    `json:"allowed_actions,omitempty"`
	OfferedSessionScopeIDs []string                    `json:"offered_session_scope_ids,omitempty"`
	OfferedDataClasses     []string                    `json:"offered_data_classes,omitempty"`
	OfferedComputeZones    []string                    `json:"offered_compute_zones,omitempty"`
	OfferedActions         []string                    `json:"offered_actions,omitempty"`
	Resource               string                      `json:"resource,omitempty"`
	Reason                 string                      `json:"reason,omitempty"`
	Metadata               map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationAssuranceIntakeRequest struct {
	ActorIdentity json.RawMessage                                             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt                                 `json:"policy_receipt,omitempty"`
	Bundle        *securecellsintegration.SecureCellFederationAssuranceBundle `json:"bundle,omitempty"`
	Reason        string                                                      `json:"reason,omitempty"`
	Metadata      map[string]string                                           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentPublishRequest struct {
	ActorIdentity            json.RawMessage                                             `json:"actor_identity,omitempty"`
	PolicyReceipt            *policy.SignedPolicyReceipt                                 `json:"policy_receipt,omitempty"`
	Severity                 securecellsintegration.SecureCellFederationIncidentSeverity `json:"severity,omitempty"`
	Category                 securecellsintegration.SecureCellFederationIncidentCategory `json:"category,omitempty"`
	Summary                  string                                                      `json:"summary,omitempty"`
	Description              string                                                      `json:"description,omitempty"`
	ContractIDs              []string                                                    `json:"contract_ids,omitempty"`
	SessionIDs               []string                                                    `json:"session_ids,omitempty"`
	ThreadIDs                []string                                                    `json:"thread_ids,omitempty"`
	SharedOutputIDs          []string                                                    `json:"shared_output_ids,omitempty"`
	SessionExchangeIDs       []string                                                    `json:"session_exchange_ids,omitempty"`
	AutoContainmentRequested *bool                                                       `json:"auto_containment_requested,omitempty"`
	ExpiresAt                *time.Time                                                  `json:"expires_at,omitempty"`
	Reason                   string                                                      `json:"reason,omitempty"`
	Metadata                 map[string]string                                           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentResolveRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentBulletinIntakeRequest struct {
	ActorIdentity json.RawMessage                                              `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt                                  `json:"policy_receipt,omitempty"`
	Bulletin      *securecellsintegration.SecureCellFederationIncidentBulletin `json:"bulletin,omitempty"`
	Reason        string                                                       `json:"reason,omitempty"`
	Metadata      map[string]string                                            `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportBundleIntakeRequest struct {
	ActorIdentity json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	Bundle        *securecellsintegration.SecureCellFederationIncidentReportBundle `json:"bundle,omitempty"`
	Reason        string                                                           `json:"reason,omitempty"`
	Metadata      map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportAmendmentBundleIntakeRequest struct {
	ActorIdentity json.RawMessage                                                           `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt                                               `json:"policy_receipt,omitempty"`
	Bundle        *securecellsintegration.SecureCellFederationIncidentReportAmendmentBundle `json:"bundle,omitempty"`
	Reason        string                                                                    `json:"reason,omitempty"`
	Metadata      map[string]string                                                         `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealBundleIntakeRequest struct {
	ActorIdentity json.RawMessage                                                                    `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt                                                        `json:"policy_receipt,omitempty"`
	Bundle        *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealBundle `json:"bundle,omitempty"`
	Reason        string                                                                             `json:"reason,omitempty"`
	Metadata      map[string]string                                                                  `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleIntakeRequest struct {
	ActorIdentity json.RawMessage                                                                                                 `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt                                                                                     `json:"policy_receipt,omitempty"`
	Bundle        *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle `json:"bundle,omitempty"`
	Reason        string                                                                                                          `json:"reason,omitempty"`
	Metadata      map[string]string                                                                                               `json:"metadata,omitempty"`
}

type secureCellFederationIncidentResponseAcknowledgeRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentResponseEscalateRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	TierID        string                      `json:"tier_id,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentRemediationAttestationRequest struct {
	ActorIdentity  json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt  *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	AttestingParty securecellsintegration.SecureCellFederationIncidentResponseParty `json:"attesting_party,omitempty"`
	Summary        string                                                           `json:"summary,omitempty"`
	Description    string                                                           `json:"description,omitempty"`
	EvidenceIDs    []string                                                         `json:"evidence_ids,omitempty"`
	Reason         string                                                           `json:"reason,omitempty"`
	Metadata       map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentRemediationVerificationRequest struct {
	ActorIdentity         json.RawMessage                                                                    `json:"actor_identity,omitempty"`
	PolicyReceipt         *policy.SignedPolicyReceipt                                                        `json:"policy_receipt,omitempty"`
	ReviewingParty        securecellsintegration.SecureCellFederationIncidentResponseParty                   `json:"reviewing_party,omitempty"`
	Decision              securecellsintegration.SecureCellFederationIncidentRemediationVerificationDecision `json:"decision,omitempty"`
	VerifiedAttestationID string                                                                             `json:"verified_attestation_id,omitempty"`
	Summary               string                                                                             `json:"summary,omitempty"`
	Description           string                                                                             `json:"description,omitempty"`
	EvidenceIDs           []string                                                                           `json:"evidence_ids,omitempty"`
	Reason                string                                                                             `json:"reason,omitempty"`
	Metadata              map[string]string                                                                  `json:"metadata,omitempty"`
}

type secureCellFederationIncidentClosureAttestationRequest struct {
	ActorIdentity  json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt  *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	AttestingParty securecellsintegration.SecureCellFederationIncidentResponseParty `json:"attesting_party,omitempty"`
	Summary        string                                                           `json:"summary,omitempty"`
	Description    string                                                           `json:"description,omitempty"`
	EvidenceIDs    []string                                                         `json:"evidence_ids,omitempty"`
	Reason         string                                                           `json:"reason,omitempty"`
	Metadata       map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentResponseDisputeRequest struct {
	ActorIdentity         json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt         *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	DisputingParty        securecellsintegration.SecureCellFederationIncidentResponseParty `json:"disputing_party,omitempty"`
	RelatedVerificationID string                                                           `json:"related_verification_id,omitempty"`
	RelatedClosureID      string                                                           `json:"related_closure_id,omitempty"`
	Summary               string                                                           `json:"summary,omitempty"`
	Description           string                                                           `json:"description,omitempty"`
	EvidenceIDs           []string                                                         `json:"evidence_ids,omitempty"`
	Reason                string                                                           `json:"reason,omitempty"`
	Metadata              map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportPlanRequest struct {
	ActorIdentity    json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt    *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	ReportingParty   securecellsintegration.SecureCellFederationIncidentResponseParty `json:"reporting_party,omitempty"`
	Regulator        string                                                           `json:"regulator,omitempty"`
	Jurisdiction     string                                                           `json:"jurisdiction,omitempty"`
	Framework        string                                                           `json:"framework,omitempty"`
	ReportType       string                                                           `json:"report_type,omitempty"`
	Summary          string                                                           `json:"summary,omitempty"`
	Description      string                                                           `json:"description,omitempty"`
	RequiredSections []string                                                         `json:"required_sections,omitempty"`
	EvidenceIDs      []string                                                         `json:"evidence_ids,omitempty"`
	DueAt            *time.Time                                                       `json:"due_at,omitempty"`
	Reason           string                                                           `json:"reason,omitempty"`
	Metadata         map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportSubmitRequest struct {
	ActorIdentity       json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt       *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	SubmissionReference string                      `json:"submission_reference,omitempty"`
	Summary             string                      `json:"summary,omitempty"`
	Description         string                      `json:"description,omitempty"`
	EvidenceIDs         []string                    `json:"evidence_ids,omitempty"`
	Reason              string                      `json:"reason,omitempty"`
	Metadata            map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportAcknowledgeRequest struct {
	ActorIdentity            json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt            *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	AcknowledgingParty       securecellsintegration.SecureCellFederationIncidentResponseParty `json:"acknowledging_party,omitempty"`
	AcknowledgementReference string                                                           `json:"acknowledgement_reference,omitempty"`
	Reason                   string                                                           `json:"reason,omitempty"`
	Metadata                 map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportAmendRequest struct {
	ActorIdentity   json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt   *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Summary         string                      `json:"summary,omitempty"`
	Description     string                      `json:"description,omitempty"`
	ChangedSections []string                    `json:"changed_sections,omitempty"`
	EvidenceIDs     []string                    `json:"evidence_ids,omitempty"`
	Reason          string                      `json:"reason,omitempty"`
	Metadata        map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportAmendmentSubmitRequest struct {
	ActorIdentity       json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt       *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	SubmissionReference string                      `json:"submission_reference,omitempty"`
	Summary             string                      `json:"summary,omitempty"`
	Description         string                      `json:"description,omitempty"`
	EvidenceIDs         []string                    `json:"evidence_ids,omitempty"`
	Reason              string                      `json:"reason,omitempty"`
	Metadata            map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportAmendmentAcknowledgeRequest struct {
	ActorIdentity            json.RawMessage                                                  `json:"actor_identity,omitempty"`
	PolicyReceipt            *policy.SignedPolicyReceipt                                      `json:"policy_receipt,omitempty"`
	AcknowledgingParty       securecellsintegration.SecureCellFederationIncidentResponseParty `json:"acknowledging_party,omitempty"`
	AcknowledgementReference string                                                           `json:"acknowledgement_reference,omitempty"`
	Reason                   string                                                           `json:"reason,omitempty"`
	Metadata                 map[string]string                                                `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportReconciliationAcknowledgeRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportReconciliationDisputeRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	Divergences   []string                    `json:"divergences,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportReconciliationResolveRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportAmendmentReconciliationAcknowledgeRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportAmendmentReconciliationDisputeRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	Divergences   []string                    `json:"divergences,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportAmendmentReconciliationResolveRequest struct {
	ActorIdentity json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	Metadata      map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAcknowledgeRequest struct {
	ActorIdentity         json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt         *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	CounterpartyReference string                      `json:"counterparty_reference,omitempty"`
	Reason                string                      `json:"reason,omitempty"`
	Metadata              map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportAmendmentReconciliationCorrectionAttestationRequest struct {
	ActorIdentity          json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt          *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	CounterpartySnapshotID string                      `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyReference  string                      `json:"counterparty_reference,omitempty"`
	Reason                 string                      `json:"reason,omitempty"`
	Metadata               map[string]string           `json:"metadata,omitempty"`
}

type secureCellFederationIncidentReportAmendmentReconciliationResolutionAttestationRequest struct {
	ActorIdentity         json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt         *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	CounterpartyReference string                      `json:"counterparty_reference,omitempty"`
	Reason                string                      `json:"reason,omitempty"`
	Metadata              map[string]string           `json:"metadata,omitempty"`
}

type secureCellMemberMutationRequest struct {
	ActorIdentity       json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt       *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	ParticipantDID      string                      `json:"participant_did,omitempty"`
	Reason              string                      `json:"reason,omitempty"`
	QuarantineExpiresAt *time.Time                  `json:"quarantine_expires_at,omitempty"`
	Metadata            map[string]string           `json:"metadata,omitempty"`
}

type secureCellLifecycleRequest struct {
	ActorIdentity     json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt     *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Reason            string                      `json:"reason,omitempty"`
	Comment           string                      `json:"comment,omitempty"`
	RelatedOutputIDs  []string                    `json:"related_output_ids,omitempty"`
	ApprovalThreshold *int                        `json:"approval_threshold,omitempty"`
	ApprovalVote      string                      `json:"approval_vote,omitempty"`
	VoteChoice        string                      `json:"vote_choice,omitempty"`
	VoteRole          string                      `json:"vote_role,omitempty"`
	DelegatedToDID    string                      `json:"delegated_to_did,omitempty"`
	EscalationReason  string                      `json:"escalation_reason,omitempty"`
	OutcomeBundleID   string                      `json:"outcome_bundle_id,omitempty"`
	OutcomeBundleName string                      `json:"outcome_bundle_name,omitempty"`
	OutcomeBundleType string                      `json:"outcome_bundle_type,omitempty"`
	DeadlineAt        *time.Time                  `json:"deadline_at,omitempty"`
	PolicyTemplate    string                      `json:"policy_template,omitempty"`
	AutoEscalation    *bool                       `json:"auto_escalation,omitempty"`
	EffectiveAt       *time.Time                  `json:"effective_at,omitempty"`
	Metadata          map[string]string           `json:"metadata,omitempty"`
}

type secureCellSessionStartRequest struct {
	ActorIdentity   json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt   *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Name            string                      `json:"name,omitempty"`
	Purpose         string                      `json:"purpose,omitempty"`
	ParticipantDIDs []string                    `json:"participant_dids,omitempty"`
	DataClasses     []string                    `json:"data_classes,omitempty"`
	Reason          string                      `json:"reason,omitempty"`
	Metadata        map[string]string           `json:"metadata,omitempty"`
}

type secureCellSessionThreadStartRequest struct {
	ActorIdentity   json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt   *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Name            string                      `json:"name,omitempty"`
	Purpose         string                      `json:"purpose,omitempty"`
	ParticipantDIDs []string                    `json:"participant_dids,omitempty"`
	DataClasses     []string                    `json:"data_classes,omitempty"`
	Reason          string                      `json:"reason,omitempty"`
	Metadata        map[string]string           `json:"metadata,omitempty"`
}

type secureCellSessionShareRequest struct {
	ActorIdentity  json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt  *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Name           string                      `json:"name,omitempty"`
	ArtifactType   string                      `json:"artifact_type,omitempty"`
	Classification string                      `json:"classification,omitempty"`
	Resource       string                      `json:"resource,omitempty"`
	Summary        string                      `json:"summary,omitempty"`
	SharedWith     []string                    `json:"shared_with,omitempty"`
	IntegrityHash  string                      `json:"integrity_hash,omitempty"`
	Reason         string                      `json:"reason,omitempty"`
	Metadata       map[string]string           `json:"metadata,omitempty"`
}

type secureCellSessionExchangeRequest struct {
	ActorIdentity  json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt  *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Name           string                      `json:"name,omitempty"`
	ExchangeType   string                      `json:"exchange_type,omitempty"`
	Classification string                      `json:"classification,omitempty"`
	Resource       string                      `json:"resource,omitempty"`
	Summary        string                      `json:"summary,omitempty"`
	Recipients     []string                    `json:"recipients,omitempty"`
	IntegrityHash  string                      `json:"integrity_hash,omitempty"`
	Reason         string                      `json:"reason,omitempty"`
	Metadata       map[string]string           `json:"metadata,omitempty"`
}

type secureCellThreadMessageRequest struct {
	ActorIdentity  json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt  *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	Name           string                      `json:"name,omitempty"`
	ExchangeType   string                      `json:"exchange_type,omitempty"`
	Classification string                      `json:"classification,omitempty"`
	Resource       string                      `json:"resource,omitempty"`
	Summary        string                      `json:"summary,omitempty"`
	Recipients     []string                    `json:"recipients,omitempty"`
	IntegrityHash  string                      `json:"integrity_hash,omitempty"`
	Reason         string                      `json:"reason,omitempty"`
	Metadata       map[string]string           `json:"metadata,omitempty"`
}

type secureCellThreadDecisionRequest struct {
	ActorIdentity         json.RawMessage                                             `json:"actor_identity,omitempty"`
	PolicyReceipt         *policy.SignedPolicyReceipt                                 `json:"policy_receipt,omitempty"`
	Title                 string                                                      `json:"title,omitempty"`
	Summary               string                                                      `json:"summary,omitempty"`
	Classification        string                                                      `json:"classification,omitempty"`
	GovernanceTemplate    string                                                      `json:"governance_template,omitempty"`
	SLATemplate           string                                                      `json:"sla_template,omitempty"`
	SectorPolicyPack      string                                                      `json:"sector_policy_pack,omitempty"`
	ApprovalThreshold     *int                                                        `json:"approval_threshold,omitempty"`
	EligibleApproverDIDs  []string                                                    `json:"eligible_approver_dids,omitempty"`
	RequiredApproverRoles []string                                                    `json:"required_approver_roles,omitempty"`
	AllowedVoteChoices    []securecellsintegration.SecureCellThreadDecisionVoteChoice `json:"allowed_vote_choices,omitempty"`
	RejectorRoles         []string                                                    `json:"rejector_roles,omitempty"`
	AbstainerRoles        []string                                                    `json:"abstainer_roles,omitempty"`
	ReopenRoles           []string                                                    `json:"reopen_roles,omitempty"`
	EscalationLadder      []securecellsintegration.SecureCellDecisionEscalationTier   `json:"escalation_ladder,omitempty"`
	AutoEscalateToDID     string                                                      `json:"auto_escalate_to_did,omitempty"`
	EscalationDueAt       *time.Time                                                  `json:"escalation_due_at,omitempty"`
	ResolutionDueAt       *time.Time                                                  `json:"resolution_due_at,omitempty"`
	RelatedExchangeIDs    []string                                                    `json:"related_exchange_ids,omitempty"`
	RelatedOutputIDs      []string                                                    `json:"related_output_ids,omitempty"`
	DeadlineAt            *time.Time                                                  `json:"deadline_at,omitempty"`
	PolicyTemplate        string                                                      `json:"policy_template,omitempty"`
	AutoEscalation        *bool                                                       `json:"auto_escalation,omitempty"`
	Reason                string                                                      `json:"reason,omitempty"`
	Metadata              map[string]string                                           `json:"metadata,omitempty"`
}

type secureCellSessionMemberMutationRequest struct {
	ActorIdentity  json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt  *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	ParticipantDID string                      `json:"participant_did,omitempty"`
	Reason         string                      `json:"reason,omitempty"`
	Metadata       map[string]string           `json:"metadata,omitempty"`
}

type secureCellBulkMemberMutationRequest struct {
	ActorIdentity       json.RawMessage             `json:"actor_identity,omitempty"`
	PolicyReceipt       *policy.SignedPolicyReceipt `json:"policy_receipt,omitempty"`
	ParticipantDIDs     []string                    `json:"participant_dids,omitempty"`
	Reason              string                      `json:"reason,omitempty"`
	QuarantineExpiresAt *time.Time                  `json:"quarantine_expires_at,omitempty"`
	Metadata            map[string]string           `json:"metadata,omitempty"`
}

type secureCellResponse struct {
	Result *securecellsintegration.SecureCellResult `json:"result,omitempty"`
	Error  string                                   `json:"error,omitempty"`
}

type secureCellArtifactsResponse struct {
	CellID                                         string                                                                                   `json:"cell_id"`
	Status                                         securecellsintegration.SecureCellStatus                                                  `json:"status"`
	Participants                                   []securecellsintegration.SecureCellParticipantState                                      `json:"participants,omitempty"`
	FederationOrganizations                        []securecellsintegration.SecureCellFederationOrganization                                `json:"federation_organizations,omitempty"`
	FederationInvitations                          []securecellsintegration.SecureCellFederationInvitation                                  `json:"federation_invitations,omitempty"`
	FederationCounterproposals                     []securecellsintegration.SecureCellFederationCounterproposal                             `json:"federation_counterproposals,omitempty"`
	FederationContracts                            []securecellsintegration.SecureCellFederationContract                                    `json:"federation_contracts,omitempty"`
	FederationCounterpartyAssurance                []securecellsintegration.SecureCellFederationCounterpartyAssuranceSnapshot               `json:"federation_counterparty_assurance,omitempty"`
	FederationIncidents                            []securecellsintegration.SecureCellFederationIncident                                    `json:"federation_incidents,omitempty"`
	FederationCounterpartyIncidents                []securecellsintegration.SecureCellFederationCounterpartyIncidentSnapshot                `json:"federation_counterparty_incidents,omitempty"`
	FederationCounterpartyIncidentReports          []securecellsintegration.SecureCellFederationCounterpartyIncidentReportSnapshot          `json:"federation_counterparty_incident_reports,omitempty"`
	FederationCounterpartyIncidentReportAmendments []securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot `json:"federation_counterparty_incident_report_amendments,omitempty"`
	FederationIncidentResponses                    []securecellsintegration.SecureCellFederationIncidentResponse                            `json:"federation_incident_responses,omitempty"`
	Sessions                                       []securecellsintegration.SecureCellSession                                               `json:"sessions,omitempty"`
	Threads                                        []securecellsintegration.SecureCellSessionThread                                         `json:"threads,omitempty"`
	Decisions                                      []securecellsintegration.SecureCellThreadDecision                                        `json:"decisions,omitempty"`
	DecisionOutcomes                               []securecellsintegration.SecureCellThreadDecisionOutcome                                 `json:"decision_outcomes,omitempty"`
	SharedOutputs                                  []securecellsintegration.SecureCellSharedOutput                                          `json:"shared_outputs,omitempty"`
	SessionExchanges                               []securecellsintegration.SecureCellSessionExchange                                       `json:"session_exchanges,omitempty"`
	Transitions                                    []securecellsintegration.SecureCellTransition                                            `json:"transitions,omitempty"`
	CreationReceipt                                *policy.SignedPolicyReceipt                                                              `json:"creation_receipt,omitempty"`
	ActivationReceipt                              *policy.SignedPolicyReceipt                                                              `json:"activation_receipt,omitempty"`
	ConfidentialExecution                          *confidential.VerificationSummary                                                        `json:"confidential_execution,omitempty"`
	ExecutionAttestations                          []evidence.Attestation                                                                   `json:"execution_attestations,omitempty"`
	ExecutionSeal                                  *evidence.Seal                                                                           `json:"execution_seal,omitempty"`
	ControlLedgerID                                string                                                                                   `json:"control_ledger_id,omitempty"`
	ControlLedgerContentHash                       string                                                                                   `json:"control_ledger_content_hash,omitempty"`
	ControlSummary                                 *evidence.ControlLedgerSummary                                                           `json:"control_summary,omitempty"`
	PortablePackageHash                            string                                                                                   `json:"portable_package_hash,omitempty"`
	PortablePackageSigned                          bool                                                                                     `json:"portable_package_signed"`
	PortablePackageAnchored                        bool                                                                                     `json:"portable_package_anchored"`
}

type secureCellListResponse struct {
	Items []securecellsintegration.SecureCellSummary `json:"items"`
}

type secureCellQuarantineExpiryListResponse struct {
	Items []securecellsintegration.SecureCellQuarantineExpiry `json:"items"`
}

type secureCellBulkMutationResponse struct {
	Result *securecellsintegration.SecureCellBulkMemberTransitionResult `json:"result,omitempty"`
}

type secureCellFederationResponse struct {
	CellID                               string                                                                                   `json:"cell_id"`
	Organizations                        []securecellsintegration.SecureCellFederationOrganization                                `json:"organizations,omitempty"`
	Invitations                          []securecellsintegration.SecureCellFederationInvitation                                  `json:"invitations,omitempty"`
	Counterproposals                     []securecellsintegration.SecureCellFederationCounterproposal                             `json:"counterproposals,omitempty"`
	Contracts                            []securecellsintegration.SecureCellFederationContract                                    `json:"contracts,omitempty"`
	CounterpartyAssurance                []securecellsintegration.SecureCellFederationCounterpartyAssuranceSnapshot               `json:"counterparty_assurance,omitempty"`
	Incidents                            []securecellsintegration.SecureCellFederationIncident                                    `json:"incidents,omitempty"`
	CounterpartyIncidents                []securecellsintegration.SecureCellFederationCounterpartyIncidentSnapshot                `json:"counterparty_incidents,omitempty"`
	CounterpartyIncidentReports          []securecellsintegration.SecureCellFederationCounterpartyIncidentReportSnapshot          `json:"counterparty_incident_reports,omitempty"`
	CounterpartyIncidentReportAmendments []securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot `json:"counterparty_incident_report_amendments,omitempty"`
	IncidentResponses                    []securecellsintegration.SecureCellFederationIncidentResponse                            `json:"incident_responses,omitempty"`
	PortablePackageHash                  string                                                                                   `json:"portable_package_hash,omitempty"`
	PortablePackageSigned                bool                                                                                     `json:"portable_package_signed"`
	PortablePackageAnchored              bool                                                                                     `json:"portable_package_anchored"`
}

type secureCellFederationOrganizationListResponse struct {
	Items []securecellsintegration.SecureCellFederationOrganizationSummary `json:"items"`
}

type secureCellFederationInvitationListResponse struct {
	Items []securecellsintegration.SecureCellFederationInvitationSummary `json:"items"`
}

type secureCellFederationCounterproposalListResponse struct {
	Items []securecellsintegration.SecureCellFederationCounterproposalSummary `json:"items"`
}

type secureCellFederationContractListResponse struct {
	Items []securecellsintegration.SecureCellFederationContractSummary `json:"items"`
}

type secureCellFederationAssuranceFindingListResponse struct {
	Items []securecellsintegration.SecureCellFederationAssuranceFinding `json:"items"`
}

type secureCellFederationAssuranceActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationAssuranceActionRecord `json:"items"`
}

type secureCellFederationCounterpartyAssuranceListResponse struct {
	Items []securecellsintegration.SecureCellFederationCounterpartyAssuranceSummary `json:"items"`
}

type secureCellFederationIncidentListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentSummary `json:"items"`
}

type secureCellFederationCounterpartyIncidentListResponse struct {
	Items []securecellsintegration.SecureCellFederationCounterpartyIncidentSummary `json:"items"`
}

type secureCellFederationCounterpartyIncidentReportListResponse struct {
	Items []securecellsintegration.SecureCellFederationCounterpartyIncidentReportSummary `json:"items"`
}

type secureCellFederationCounterpartyIncidentReportAmendmentListResponse struct {
	Items []securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentSummary `json:"items"`
}

type secureCellFederationIncidentActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentActionRecord `json:"items"`
}

type secureCellFederationIncidentResponseListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentResponseSummary `json:"items"`
}

type secureCellOverdueFederationIncidentResponseListResponse struct {
	Items []securecellsintegration.SecureCellOverdueFederationIncidentResponse `json:"items"`
}

type secureCellFederationIncidentResponseActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentResponseActionRecord `json:"items"`
}

type secureCellFederationIncidentRemediationListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentRemediationSummary `json:"items"`
}

type secureCellFederationIncidentVerificationListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentVerificationSummary `json:"items"`
}

type secureCellFederationIncidentClosureListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentClosureAttestationSummary `json:"items"`
}

type secureCellFederationIncidentDisputeListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentDisputeSummary `json:"items"`
}

type secureCellFederationIncidentReportListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentReportSummary `json:"items"`
}

type secureCellFederationIncidentReportAmendmentListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentReportAmendmentSummary `json:"items"`
}

type secureCellOverdueFederationIncidentReportListResponse struct {
	Items []securecellsintegration.SecureCellOverdueFederationIncidentReport `json:"items"`
}

type secureCellFederationIncidentReportReconciliationListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentReportReconciliationSummary `json:"items"`
}

type secureCellFederationIncidentReportAmendmentReconciliationListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationSummary `json:"items"`
}

type secureCellFederationIncidentReportReconciliationActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentReportReconciliationActionRecord `json:"items"`
}

type secureCellFederationIncidentReportAmendmentReconciliationActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionRecord `json:"items"`
}

type secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord `json:"items"`
}

type secureCellOverdueFederationIncidentReportReconciliationListResponse struct {
	Items []securecellsintegration.SecureCellOverdueFederationIncidentReportReconciliation `json:"items"`
}

type secureCellOverdueFederationIncidentReportAmendmentReconciliationListResponse struct {
	Items []securecellsintegration.SecureCellOverdueFederationIncidentReportAmendmentReconciliation `json:"items"`
}

type secureCellFederationIncidentReportReconciliationAutomationActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentReportReconciliationAutomationActionRecord `json:"items"`
}

type secureCellFederationIncidentReportAmendmentReconciliationAutomationActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionRecord `json:"items"`
}

type secureCellFederationIncidentResponseQueryResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentResponse `json:"result,omitempty"`
}

type secureCellFederationIncidentResponseBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentResponseBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentDirectiveBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentDirectiveBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentCasePackResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentCasePack `json:"result,omitempty"`
}

type secureCellFederationIncidentReportBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentReportBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentReportAmendmentBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentReportAmendmentBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentReportReconciliationBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentReportReconciliationBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentReportAmendmentReconciliationBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationBundle `json:"result,omitempty"`
}

type secureCellFederationTrustPackResponse struct {
	Result *securecellsintegration.SecureCellFederationOrganizationTrustPack `json:"result,omitempty"`
}

type secureCellFederationAssuranceReportResponse struct {
	Result *securecellsintegration.SecureCellFederationAssuranceReport `json:"result,omitempty"`
}

type secureCellFederationAssuranceBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationAssuranceBundle `json:"result,omitempty"`
}

type secureCellFederationIncidentBulletinResponse struct {
	Result *securecellsintegration.SecureCellFederationIncidentBulletin `json:"result,omitempty"`
}

type secureCellFederationInvitationBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationInvitationBundle `json:"result,omitempty"`
}

type secureCellFederationContractBundleResponse struct {
	Result *securecellsintegration.SecureCellFederationContractBundle `json:"result,omitempty"`
}

type secureCellDecisionListResponse struct {
	Items []securecellsintegration.SecureCellThreadDecision `json:"items"`
}

type secureCellDecisionQueryResponse struct {
	Result *securecellsintegration.SecureCellThreadDecision `json:"result,omitempty"`
}

type secureCellDecisionDeliberationResponse struct {
	Result           *securecellsintegration.SecureCellThreadDecision         `json:"result,omitempty"`
	DecisionOutcomes []securecellsintegration.SecureCellThreadDecisionOutcome `json:"decision_outcomes,omitempty"`
	SharedOutputs    []securecellsintegration.SecureCellSharedOutput          `json:"shared_outputs,omitempty"`
	SessionExchanges []securecellsintegration.SecureCellSessionExchange       `json:"session_exchanges,omitempty"`
}

type secureCellDecisionOutcomeListResponse struct {
	Items []securecellsintegration.SecureCellThreadDecisionOutcome `json:"items"`
}

type secureCellEventListResponse struct {
	Items []secureCellAuditEventRecord `json:"items"`
}

type secureCellWebhookDeliveryListResponse struct {
	Items []secureCellWebhookDeliveryRecord `json:"items"`
}

type secureCellOverdueDecisionListResponse struct {
	Items []securecellsintegration.SecureCellOverdueDecision `json:"items"`
}

type secureCellDecisionAutomationActionListResponse struct {
	Items []securecellsintegration.SecureCellDecisionAutomationActionRecord `json:"items"`
}

type secureCellOverdueFederationCounterproposalListResponse struct {
	Items []securecellsintegration.SecureCellOverdueFederationCounterproposal `json:"items"`
}

type secureCellFederationAutomationActionListResponse struct {
	Items []securecellsintegration.SecureCellFederationAutomationActionRecord `json:"items"`
}

type secureCellDecisionSLATemplateListResponse struct {
	Items []securecellsintegration.SecureCellDecisionSLATemplateSummary `json:"items"`
}

type appSecureCellSealer struct {
	app         *AethelredApp
	requestedBy string
}

func (s *appSecureCellSealer) CreateSeal(_ context.Context, req sealsdk.SealRequest) (*sealsdk.SealResponse, error) {
	if s == nil || s.app == nil {
		return nil, fmt.Errorf("secure cells sealer is unavailable")
	}
	ctx := safeAuditKeeperContext(s.app)
	if ctx == nil {
		return nil, fmt.Errorf("secure cells sealer has no keeper context")
	}
	sdkCtx, ok := ctx.(cosmossdk.Context)
	if !ok {
		return nil, fmt.Errorf("secure cells sealer could not unwrap sdk context")
	}
	if sdkCtx.BlockHeight() <= 0 {
		sdkCtx = sdkCtx.WithBlockHeight(1)
		ctx = sdkCtx
	}

	requestedBy := strings.TrimSpace(s.requestedBy)
	if requestedBy == "" {
		requestedBy = authtypes.NewModuleAddress(pouwtypes.ModuleName).String()
	}
	seal := sealtypes.NewDigitalSeal(req.ModelHash, req.InputHash, req.OutputHash, sdkCtx.BlockHeight(), requestedBy, req.Purpose)
	if req.ZKProof != nil {
		seal.SetZKProof(req.ZKProof)
	}
	for _, attestation := range req.TEEAttestations {
		seal.AddAttestation(attestation)
	}
	if seal.IsVerified() {
		seal.Activate()
	}
	if err := s.app.SealKeeper.CreateSeal(ctx, seal); err != nil {
		return nil, err
	}
	return &sealsdk.SealResponse{
		SealID:         seal.Id,
		Status:         seal.Status,
		Attestations:   append([]*sealtypes.TEEAttestation(nil), seal.TeeAttestations...),
		Proof:          seal.ZkProof,
		Timestamp:      seal.Timestamp.AsTime().UTC(),
		RegulatoryInfo: seal.RegulatoryInfo,
		BlockHeight:    seal.BlockHeight,
		RequestedBy:    seal.RequestedBy,
		Purpose:        seal.Purpose,
		ValidatorSet:   append([]string(nil), seal.ValidatorSet...),
	}, nil
}

func (app *AethelredApp) initSecureCellsInfrastructure(appOpts servertypes.AppOptions) {
	controlLedgerDir := resolveSecureCellControlLedgerDir(appOpts)
	ledgerStore, err := evidence.NewFileControlLedgerStore(controlLedgerDir)
	if err != nil {
		app.Logger().Error("Secure Cells API initialization failed while creating the control-ledger store",
			"error", err,
			"control_ledger_dir", controlLedgerDir,
		)
		return
	}
	workflowStoreDir := resolveSecureCellWorkflowStoreDir(appOpts)
	workflowStore, err := securecellsintegration.NewFileSecureCellStore(workflowStoreDir)
	if err != nil {
		app.Logger().Error("Secure Cells API initialization failed while creating the workflow store",
			"error", err,
			"workflow_store_dir", workflowStoreDir,
		)
		return
	}

	policySignerKey, policySigner, signerMode, signerMessage, err := resolveSecureCellPolicySigner(appOpts)
	if err != nil {
		app.Logger().Error("Secure Cells API initialization failed while resolving the secure-cell policy signer", "error", err)
		return
	}

	webhookConfig := resolveSecureCellWebhookConfig(appOpts)
	secureCellRuntime := newSecureCellLifecycleRuntime(app, webhookConfig)
	requestedBy := firstNonEmpty(cast.ToString(appOpts.Get("aethelred.secure_cells.signer_address")), cast.ToString(appOpts.Get("secure_cells.signer_address")), app.PouwKeeper.GetAuthority(), authtypes.NewModuleAddress(pouwtypes.ModuleName).String())
	confidentialKeys := map[string]*ecdsa.PublicKey{
		policySigner: &policySignerKey.PublicKey,
	}
	confidentialPolicy := resolveConfidentialExecutionPolicy(appOpts, "aethelred.secure_cells", "secure_cells", false, confidentialKeys)
	service, err := securecellsintegration.NewService(securecellsintegration.ServiceConfig{
		PolicySignerKey:     policySignerKey,
		PolicySigner:        policySigner,
		CredentialIssuerKey: policySignerKey,
		CredentialIssuer:    policySigner,
		Sealer: &appSecureCellSealer{
			app:         app,
			requestedBy: requestedBy,
		},
		LedgerStore:          ledgerStore,
		WorkflowStore:        workflowStore,
		Framework:            "Secure Cells v1",
		ConfidentialAttestor: newWorkflowTEEAttestor(app, "secure_cell", policySigner, policySignerKey),
		ConfidentialPolicy:   confidentialPolicy,
		FederationAssuranceBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationAssuranceBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationAssuranceBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentBulletinSigner: func(ctx context.Context, bulletin *securecellsintegration.SecureCellFederationIncidentBulletin) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentBulletinEd25519(bulletin, privateKey, signer, true)
		},
		FederationIncidentResponseBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentResponseBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentResponseBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentDirectiveBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentDirectiveBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentDirectiveBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentDirectiveExtensionAppealBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentDirectiveExtensionAppealBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentDirectiveExtensionAppealReconciliationBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentDirectiveExtensionAppealReconciliationBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentReportBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentReportBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentReportBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentReportAmendmentBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentReportAmendmentBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentReportAmendmentBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentReportReconciliationBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentReportReconciliationBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentReportReconciliationBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentReportAmendmentReconciliationBundleSigner: func(ctx context.Context, bundle *securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationBundle) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentReportAmendmentReconciliationBundleEd25519(bundle, privateKey, signer, true)
		},
		FederationIncidentCasePackSigner: func(ctx context.Context, pack *securecellsintegration.SecureCellFederationIncidentCasePack) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return securecellsintegration.SignFederationIncidentCasePackEd25519(pack, privateKey, signer, true)
		},
		PackageSignerFunc: func(ctx context.Context, pkg *evidence.PortableControlLedgerPackage) error {
			signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
			if !ok {
				return nil
			}
			return pkg.SignEd25519(privateKey, signer)
		},
		PackageAnchorer: func(_ context.Context, pkg *evidence.PortableControlLedgerPackage) error {
			anchor := anchorPortableControlLedgerPackage(app, pkg)
			if anchor == nil {
				return nil
			}
			pkg.AuditAnchor = anchor
			return nil
		},
		EventPublisher: secureCellRuntime.Publish,
	})
	if err != nil {
		app.Logger().Error("Secure Cells API initialization failed while constructing the lifecycle runtime-backed service", "error", err)
		return
	}

	app.secureCellService = service
	secureCellAuth, authMode, authMessage := resolveSecureCellAuthorizer(app, appOpts)
	app.secureCellAuth = secureCellAuth
	app.secureCellControlLedgerDir = controlLedgerDir
	app.secureCellWorkflowStoreDir = workflowStoreDir
	app.secureCellRuntime = secureCellRuntime
	app.secureCellExpirySweeper = newSecureCellExpirySweeper(app, service, resolveSecureCellExpirySweepInterval(appOpts))
	if signerMode == "ephemeral" {
		app.Logger().Warn("Secure Cells API initialized with an ephemeral policy signer",
			"control_ledger_dir", controlLedgerDir,
			"workflow_store_dir", workflowStoreDir,
			"policy_signer", policySigner,
			"policy_signer_mode", signerMode,
			"policy_signer_message", signerMessage,
			"write_auth_mode", authMode,
			"write_auth_message", authMessage,
			"webhook_endpoints", len(webhookConfig.Endpoints),
			"expiry_sweep_interval", resolveSecureCellExpirySweepInterval(appOpts),
		)
		return
	}
	app.Logger().Info("Secure Cells API initialized",
		"control_ledger_dir", controlLedgerDir,
		"workflow_store_dir", workflowStoreDir,
		"policy_signer", policySigner,
		"policy_signer_mode", signerMode,
		"policy_signer_message", signerMessage,
		"write_auth_mode", authMode,
		"write_auth_message", authMessage,
		"webhook_endpoints", len(webhookConfig.Endpoints),
		"expiry_sweep_interval", resolveSecureCellExpirySweepInterval(appOpts),
	)
}

func (app *AethelredApp) SecureCellsCreateHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeSecureCellAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.secureCellService == nil {
			writeSecureCellAPIError(w, http.StatusServiceUnavailable, "secure cell service is unavailable")
			return
		}

		var req secureCellCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell request: "+err.Error())
			return
		}

		authCtx, err := app.authorizeSecureCellCreate(r, &req)
		if err != nil {
			writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
			return
		}

		identity, err := decodeFinanceAgentIdentity(req.Identity)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return
		}

		req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
		result, err := app.secureCellService.CreateCell(r.Context(), securecellsintegration.SecureCellRequest{
			OwnerIdentity: identity,
			Name:          req.Name,
			Purpose:       req.Purpose,
			Resource:      req.Resource,
			Jurisdiction:  req.Jurisdiction,
			Participants:  req.Participants,
			Policy:        req.Policy,
			Metadata:      req.Metadata,
		})
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
			return
		}
		if result != nil && result.Status == securecellsintegration.SecureCellStatusRejected {
			writeSecureCellJSON(w, http.StatusForbidden, secureCellResponse{Result: result, Error: result.RejectionReason})
			return
		}
		writeSecureCellJSON(w, http.StatusCreated, secureCellResponse{Result: result})
	})
}

func (app *AethelredApp) SecureCellsCollectionHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeSecureCellAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.secureCellService == nil {
			writeSecureCellAPIError(w, http.StatusServiceUnavailable, "secure cell service is unavailable")
			return
		}
		filter, err := parseSecureCellListFilter(r)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		items, err := app.secureCellService.ListCells(r.Context(), filter)
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellListResponse{Items: items})
	})
}

func (app *AethelredApp) SecureCellsExpiringQuarantinesHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeSecureCellAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.secureCellService == nil {
			writeSecureCellAPIError(w, http.StatusServiceUnavailable, "secure cell service is unavailable")
			return
		}
		before, err := parseSecureCellOptionalTime(r.URL.Query().Get("before"))
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		items, err := app.secureCellService.ListExpiringQuarantines(r.Context(), derefSecureCellTime(before))
		if err != nil {
			writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellQuarantineExpiryListResponse{Items: items})
	})
}

func (app *AethelredApp) SecureCellsGetHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeSecureCellAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.secureCellService == nil {
			writeSecureCellAPIError(w, http.StatusServiceUnavailable, "secure cell service is unavailable")
			return
		}

		if app.handleSecureCellGovernmentAgentExecutionReceiptLedgerGet(w, r) {
			return
		}

		if app.handleSecureCellGovernmentAgentExecutionWitnessGet(w, r) {
			return
		}

		if app.handleSecureCellGovernmentAgentRehearsalGet(w, r) {
			return
		}

		if app.handleSecureCellGovernmentAgentCarryPackGet(w, r) {
			return
		}

		if app.handleSecureCellGovernmentAgentProgramGet(w, r) {
			return
		}

		if app.handleSecureCellGovernmentAgentBlueprintGet(w, r) {
			return
		}

		if app.handleSecureCellGovernmentAgentReadinessGet(w, r) {
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/decision-sla-templates" {
			filter := parseSecureCellDecisionSLATemplateFilter(r)
			items, err := app.secureCellService.ListDecisionSLATemplates(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellDecisionSLATemplateListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/decision-sla-templates/export" {
			filter := parseSecureCellDecisionSLATemplateFilter(r)
			items, err := app.secureCellService.ListDecisionSLATemplates(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellDecisionSLATemplateExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/decisions/overdue" {
			filter, err := parseSecureCellOverdueDecisionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueDecisions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueDecisionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/decisions/overdue/export" {
			filter, err := parseSecureCellOverdueDecisionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueDecisions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueDecisionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/decisions/automation-actions" {
			filter, err := parseSecureCellDecisionAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListDecisionAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellDecisionAutomationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/decisions/automation-actions/export" {
			filter, err := parseSecureCellDecisionAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListDecisionAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellDecisionAutomationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/organizations" {
			filter, err := parseSecureCellFederationOrganizationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationOrganizations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationOrganizationListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/organizations/export" {
			filter, err := parseSecureCellFederationOrganizationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationOrganizations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationOrganizationExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/invitations" {
			filter, err := parseSecureCellFederationInvitationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationInvitations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationInvitationListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/invitations/export" {
			filter, err := parseSecureCellFederationInvitationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationInvitations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationInvitationExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterproposals" {
			filter, err := parseSecureCellFederationCounterproposalFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterproposals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterproposalListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterproposals/export" {
			filter, err := parseSecureCellFederationCounterproposalFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterproposals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationCounterproposalExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterproposals/overdue" {
			filter, err := parseSecureCellOverdueFederationCounterproposalFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationCounterproposals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationCounterproposalListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterproposals/overdue/export" {
			filter, err := parseSecureCellOverdueFederationCounterproposalFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationCounterproposals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueFederationCounterproposalExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/automation-actions" {
			filter, err := parseSecureCellFederationAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationAutomationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/automation-actions/export" {
			filter, err := parseSecureCellFederationAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationAutomationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/assurance/findings" {
			filter, err := parseSecureCellFederationAssuranceFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationAssuranceFindings(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationAssuranceFindingListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/assurance/findings/export" {
			filter, err := parseSecureCellFederationAssuranceFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationAssuranceFindings(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationAssuranceFindingExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/assurance/actions" {
			filter, err := parseSecureCellFederationAssuranceActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationAssuranceActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationAssuranceActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/assurance/actions/export" {
			filter, err := parseSecureCellFederationAssuranceActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationAssuranceActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationAssuranceActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-assurance" {
			filter, err := parseSecureCellFederationCounterpartyAssuranceFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyAssurance(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyAssuranceListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-assurance/export" {
			filter, err := parseSecureCellFederationCounterpartyAssuranceFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyAssurance(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationCounterpartyAssuranceExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incidents" {
			filter, err := parseSecureCellFederationIncidentFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidents(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incidents/export" {
			filter, err := parseSecureCellFederationIncidentFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidents(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-actions" {
			filter, err := parseSecureCellFederationIncidentActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-actions/export" {
			filter, err := parseSecureCellFederationIncidentActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-responses" {
			filter, err := parseSecureCellFederationIncidentResponseFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentResponses(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentResponseListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-responses/export" {
			filter, err := parseSecureCellFederationIncidentResponseFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentResponses(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentResponseExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-responses/overdue" {
			filter, err := parseSecureCellOverdueFederationIncidentResponseFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentResponses(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentResponseListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-responses/overdue/export" {
			filter, err := parseSecureCellOverdueFederationIncidentResponseFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentResponses(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueFederationIncidentResponseExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-response-actions" {
			filter, err := parseSecureCellFederationIncidentResponseActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentResponseActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentResponseActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-response-actions/export" {
			filter, err := parseSecureCellFederationIncidentResponseActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentResponseActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentResponseActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directives" {
			filter, err := parseSecureCellFederationIncidentDirectiveFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectives(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directives/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectives(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directives/overdue" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectives(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directives/overdue/export" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectives(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueFederationIncidentDirectiveExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extensions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extensions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extensions/overdue" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveExtensionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extensions/overdue/export" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueFederationIncidentDirectiveExtensionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-disputes" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionDisputeFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionDisputes(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionDisputeListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-disputes/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionDisputeFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionDisputes(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionDisputeExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeals" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeals/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-recusals" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealRecusalFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealRecusals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealRecusalListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-recusals/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealRecusalFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealRecusals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealRecusalExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-directive-extension-appeals" {
			filter, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentDirectiveExtensionAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-directive-extension-appeals/export" {
			filter, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentDirectiveExtensionAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliations" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliations/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenges" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallenges(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenges/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallenges(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeals" {
			filter, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeals/export" {
			filter, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals" {
			filter, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals/export" {
			filter, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-reviews" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviews(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-reviews/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviews(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals" {
			filter, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals/export" {
			filter, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals" {
			filter, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals/export" {
			filter, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundles" {
			filter, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundles(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundles/export" {
			filter, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundles(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle-review-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle-review-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleReviewActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignments/overdue" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignments(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignments/overdue/export" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignments(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-automation-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-automation-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals/overdue" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals/overdue/export" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-recusals" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-recusals/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-automation-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-automation-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-recusals" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-recusals/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/overdue" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/overdue/export" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-automation-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-automation-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-attestations" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-attestations/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliations/overdue" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensionAppealReconciliations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliations/overdue/export" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensionAppealReconciliations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-automation-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-automation-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenges/overdue" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallenges(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenges/overdue/export" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallenges(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-automation-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-reconciliation-challenge-automation-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeals/overdue" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensionAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentDirectiveExtensionAppealListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeals/overdue/export" {
			filter, err := parseSecureCellOverdueFederationIncidentDirectiveExtensionAppealFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentDirectiveExtensionAppeals(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueFederationIncidentDirectiveExtensionAppealExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-automation-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealAutomationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-appeal-automation-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAppealAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAppealAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAppealAutomationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-automation-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAutomationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-extension-automation-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveExtensionAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveExtensionAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveExtensionAutomationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-automation-actions" {
			filter, err := parseSecureCellFederationIncidentDirectiveAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveAutomationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-directive-automation-actions/export" {
			filter, err := parseSecureCellFederationIncidentDirectiveAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDirectiveAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDirectiveAutomationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-remediations" {
			filter, err := parseSecureCellFederationIncidentRemediationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentRemediations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentRemediationListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-remediations/export" {
			filter, err := parseSecureCellFederationIncidentRemediationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentRemediations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentRemediationExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-verifications" {
			filter, err := parseSecureCellFederationIncidentVerificationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentVerifications(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentVerificationListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-verifications/export" {
			filter, err := parseSecureCellFederationIncidentVerificationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentVerifications(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentVerificationExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-closures" {
			filter, err := parseSecureCellFederationIncidentClosureAttestationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentClosureAttestations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentClosureListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-closures/export" {
			filter, err := parseSecureCellFederationIncidentClosureAttestationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentClosureAttestations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentClosureExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-disputes" {
			filter, err := parseSecureCellFederationIncidentDisputeFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDisputes(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDisputeListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-disputes/export" {
			filter, err := parseSecureCellFederationIncidentDisputeFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentDisputes(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentDisputeExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-reports" {
			filter, err := parseSecureCellFederationIncidentReportFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReports(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-reports/export" {
			filter, err := parseSecureCellFederationIncidentReportFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReports(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentReportExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-amendments" {
			filter, err := parseSecureCellFederationIncidentReportAmendmentFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportAmendments(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-amendments/export" {
			filter, err := parseSecureCellFederationIncidentReportAmendmentFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportAmendments(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentReportAmendmentExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-reports/overdue" {
			filter, err := parseSecureCellOverdueFederationIncidentReportFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentReports(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentReportListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-reports/overdue/export" {
			filter, err := parseSecureCellOverdueFederationIncidentReportFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentReports(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueFederationIncidentReportExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-reports" {
			filter, err := parseSecureCellFederationCounterpartyIncidentReportFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentReports(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyIncidentReportListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-reports/export" {
			filter, err := parseSecureCellFederationCounterpartyIncidentReportFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentReports(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationCounterpartyIncidentReportExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-report-amendments" {
			filter, err := parseSecureCellFederationCounterpartyIncidentReportAmendmentFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentReportAmendments(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyIncidentReportAmendmentListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incident-report-amendments/export" {
			filter, err := parseSecureCellFederationCounterpartyIncidentReportAmendmentFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidentReportAmendments(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationCounterpartyIncidentReportAmendmentExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-reconciliations" {
			filter, err := parseSecureCellFederationIncidentReportReconciliationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportReconciliations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportReconciliationListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-reconciliations/export" {
			filter, err := parseSecureCellFederationIncidentReportReconciliationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportReconciliations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentReportReconciliationExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-amendment-reconciliations" {
			filter, err := parseSecureCellFederationIncidentReportAmendmentReconciliationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportAmendmentReconciliations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentReconciliationListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-amendment-reconciliations/export" {
			filter, err := parseSecureCellFederationIncidentReportAmendmentReconciliationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportAmendmentReconciliations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentReportAmendmentReconciliationExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-amendment-reconciliation-actions" {
			filter, err := parseSecureCellFederationIncidentReportAmendmentReconciliationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportAmendmentReconciliationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentReconciliationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-amendment-reconciliation-actions/export" {
			filter, err := parseSecureCellFederationIncidentReportAmendmentReconciliationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportAmendmentReconciliationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentReportAmendmentReconciliationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-amendment-reconciliation-attestations" {
			filter, err := parseSecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportAmendmentReconciliationCounterpartyAttestations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-amendment-reconciliation-attestations/export" {
			filter, err := parseSecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportAmendmentReconciliationCounterpartyAttestations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-amendment-reconciliations/overdue" {
			filter, err := parseSecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentReportAmendmentReconciliations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentReportAmendmentReconciliationListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-amendment-reconciliations/overdue/export" {
			filter, err := parseSecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentReportAmendmentReconciliations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueFederationIncidentReportAmendmentReconciliationExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-amendment-reconciliation-automation-actions" {
			filter, err := parseSecureCellFederationIncidentReportAmendmentReconciliationAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportAmendmentReconciliationAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentReconciliationAutomationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-amendment-reconciliation-automation-actions/export" {
			filter, err := parseSecureCellFederationIncidentReportAmendmentReconciliationAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportAmendmentReconciliationAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentReportAmendmentReconciliationAutomationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-reconciliations/overdue" {
			filter, err := parseSecureCellOverdueFederationIncidentReportReconciliationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentReportReconciliations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellOverdueFederationIncidentReportReconciliationListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-reconciliations/overdue/export" {
			filter, err := parseSecureCellOverdueFederationIncidentReportReconciliationFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListOverdueFederationIncidentReportReconciliations(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellOverdueFederationIncidentReportReconciliationExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-reconciliation-actions" {
			filter, err := parseSecureCellFederationIncidentReportReconciliationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportReconciliationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportReconciliationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-reconciliation-actions/export" {
			filter, err := parseSecureCellFederationIncidentReportReconciliationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportReconciliationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentReportReconciliationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-reconciliation-automation-actions" {
			filter, err := parseSecureCellFederationIncidentReportReconciliationAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportReconciliationAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportReconciliationAutomationActionListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/incident-report-reconciliation-automation-actions/export" {
			filter, err := parseSecureCellFederationIncidentReportReconciliationAutomationActionFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationIncidentReportReconciliationAutomationActions(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentReportReconciliationAutomationActionExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incidents" {
			filter, err := parseSecureCellFederationCounterpartyIncidentFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidents(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationCounterpartyIncidentListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/counterparty-incidents/export" {
			filter, err := parseSecureCellFederationCounterpartyIncidentFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationCounterpartyIncidents(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationCounterpartyIncidentExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/contracts" {
			filter, err := parseSecureCellFederationContractFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationContracts(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationContractListResponse{Items: items})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/federation/contracts/export" {
			filter, err := parseSecureCellFederationContractFilter(r)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			items, err := app.secureCellService.ListFederationContracts(r.Context(), filter)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := writeSecureCellFederationContractExport(w, r, items); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if r.URL.Path == secureCellsItemPrefix+"events" || r.URL.Path == secureCellsCollectionRoute+"/events" {
			filter := secureCellAuditEventFilter{
				CellID:         strings.TrimSpace(r.URL.Query().Get("cell_id")),
				ParticipantDID: strings.TrimSpace(r.URL.Query().Get("participant_did")),
				ThreadID:       strings.TrimSpace(r.URL.Query().Get("thread_id")),
				DecisionID:     strings.TrimSpace(r.URL.Query().Get("decision_id")),
				Action:         strings.TrimSpace(r.URL.Query().Get("action")),
				Actor:          strings.TrimSpace(r.URL.Query().Get("actor")),
				SinceSequence:  cast.ToUint64(strings.TrimSpace(r.URL.Query().Get("since_sequence"))),
				Limit:          cast.ToInt(strings.TrimSpace(r.URL.Query().Get("limit"))),
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellEventListResponse{Items: listSecureCellAuditEvents(app, filter)})
			return
		}

		if r.URL.Path == secureCellsCollectionRoute+"/webhook-deliveries" {
			if app.secureCellRuntime == nil {
				writeSecureCellJSON(w, http.StatusOK, secureCellWebhookDeliveryListResponse{Items: nil})
				return
			}
			filter := secureCellWebhookDeliveryFilter{
				CellID:   strings.TrimSpace(r.URL.Query().Get("cell_id")),
				EventID:  strings.TrimSpace(r.URL.Query().Get("event_id")),
				Endpoint: strings.TrimSpace(r.URL.Query().Get("endpoint")),
				Status:   secureCellWebhookDeliveryStatus(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))),
				Limit:    cast.ToInt(strings.TrimSpace(r.URL.Query().Get("limit"))),
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellWebhookDeliveryListResponse{Items: app.secureCellRuntime.ListDeliveries(filter)})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/status") && strings.Contains(r.URL.Path, "/decisions/") {
			cellID, sessionID, threadID, decisionID, err := parseSecureCellSessionThreadDecisionLookupPath(r.URL.Path, "/status")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			decision, ok := secureCellDecisionFromResult(result, sessionID, threadID, decisionID)
			if !ok {
				writeSecureCellAPIError(w, http.StatusNotFound, "secure cell decision not found")
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellDecisionQueryResponse{Result: decision})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/deliberation") && strings.Contains(r.URL.Path, "/decisions/") {
			cellID, sessionID, threadID, decisionID, err := parseSecureCellSessionThreadDecisionLookupPath(r.URL.Path, "/deliberation")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			response, ok := secureCellDecisionDeliberationProjection(result, sessionID, threadID, decisionID)
			if !ok {
				writeSecureCellAPIError(w, http.StatusNotFound, "secure cell decision not found")
				return
			}
			writeSecureCellJSON(w, http.StatusOK, response)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/outcomes") && strings.Contains(r.URL.Path, "/decisions/") {
			cellID, sessionID, threadID, decisionID, err := parseSecureCellSessionThreadDecisionLookupPath(r.URL.Path, "/outcomes")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			decision, ok := secureCellDecisionFromResult(result, sessionID, threadID, decisionID)
			if !ok {
				writeSecureCellAPIError(w, http.StatusNotFound, "secure cell decision not found")
				return
			}
			outcomes := secureCellDecisionOutcomesForDecision(result, decision)
			writeSecureCellJSON(w, http.StatusOK, secureCellDecisionOutcomeListResponse{Items: outcomes})
			return
		}

		if strings.Contains(r.URL.Path, "/federation/incident-responses/") {
			cellID, responseID, err := parseSecureCellFederationIncidentResponseActionPath(r.URL.Path, "/case-pack/export")
			if err == nil {
				pack, err := app.secureCellService.BuildFederationIncidentCasePack(r.Context(), cellID, responseID, secureCellFederationIncidentCasePackOptions(cellID, responseID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentCasePackExport(w, r, pack); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, responseID, err = parseSecureCellFederationIncidentResponseActionPath(r.URL.Path, "/case-pack")
			if err == nil {
				pack, err := app.secureCellService.BuildFederationIncidentCasePack(r.Context(), cellID, responseID, secureCellFederationIncidentCasePackOptions(cellID, responseID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentCasePackResponse{Result: pack})
				return
			}

			cellID, responseID, err = parseSecureCellFederationIncidentResponseActionPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentResponseBundle(r.Context(), cellID, responseID, secureCellFederationIncidentResponseBundleOptions(cellID, responseID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentResponseBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, responseID, err = parseSecureCellFederationIncidentResponseActionPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentResponseBundle(r.Context(), cellID, responseID, secureCellFederationIncidentResponseBundleOptions(cellID, responseID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentResponseBundleResponse{Result: bundle})
				return
			}

			cellID, responseID, err = parseSecureCellFederationIncidentResponseActionPath(r.URL.Path, "")
			if err == nil {
				result, err := app.secureCellService.GetFederationIncidentResponse(r.Context(), cellID, responseID)
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentResponseQueryResponse{Result: result})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/incident-directives/") {
			cellID, directiveID, err := parseSecureCellFederationIncidentDirectiveActionPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveBundle(r.Context(), cellID, directiveID, secureCellFederationIncidentDirectiveBundleOptions(cellID, directiveID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentDirectiveBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, directiveID, err = parseSecureCellFederationIncidentDirectiveActionPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveBundle(r.Context(), cellID, directiveID, secureCellFederationIncidentDirectiveBundleOptions(cellID, directiveID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveBundleResponse{Result: bundle})
				return
			}

			cellID, directiveID, err = parseSecureCellFederationIncidentDirectiveActionPath(r.URL.Path, "")
			if err == nil {
				result, err := app.secureCellService.GetFederationIncidentDirective(r.Context(), cellID, directiveID)
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveQueryResponse{Result: result})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeals/") {
			cellID, appealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealActionPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealBundle(r.Context(), cellID, appealID, secureCellFederationIncidentDirectiveExtensionAppealBundleOptions(cellID, appealID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentDirectiveExtensionAppealBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, appealID, err = parseSecureCellFederationIncidentDirectiveExtensionAppealActionPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealBundle(r.Context(), cellID, appealID, secureCellFederationIncidentDirectiveExtensionAppealBundleOptions(cellID, appealID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealBundleResponse{Result: bundle})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliations/") {
			cellID, comparisonKey, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealReconciliationBundle(r.Context(), cellID, comparisonKey, secureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleOptions(cellID, comparisonKey))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, comparisonKey, err = parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealReconciliationBundle(r.Context(), cellID, comparisonKey, secureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleOptions(cellID, comparisonKey))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleResponse{Result: bundle})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-reviews/") {
			cellID, reviewID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle(r.Context(), cellID, reviewID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleOptions(cellID, reviewID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, reviewID, err = parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundle(r.Context(), cellID, reviewID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleOptions(cellID, reviewID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleResponse{Result: bundle})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals/") {
			cellID, appealReviewID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(r.Context(), cellID, appealReviewID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleOptions(cellID, appealReviewID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, appealReviewID, err = parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(r.Context(), cellID, appealReviewID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleOptions(cellID, appealReviewID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleResponse{Result: bundle})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals/") {
			cellID, responseAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle(r.Context(), cellID, responseAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleOptions(cellID, responseAppealID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleExport(w, r, "", bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, responseAppealID, err = parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle(r.Context(), cellID, responseAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleOptions(cellID, responseAppealID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleResponse{Result: bundle})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals/") {
			cellID, snapshotID, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealPath(r.URL.Path, "/review-bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle(r.Context(), cellID, snapshotID, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleOptions(cellID, snapshotID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, snapshotID, err = parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealPath(r.URL.Path, "/review-bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle(r.Context(), cellID, snapshotID, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleOptions(cellID, snapshotID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleResponse{Result: bundle})
				return
			}

			cellID, snapshotID, err = parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.GetFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle(r.Context(), cellID, snapshotID)
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleExport(w, r, snapshotID, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, snapshotID, err = parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.GetFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle(r.Context(), cellID, snapshotID)
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleResponse{Result: bundle})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundles/") {
			cellID, snapshotID, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundlePath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.GetFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle(r.Context(), cellID, snapshotID)
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, snapshotID, err = parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundlePath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.GetFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle(r.Context(), cellID, snapshotID)
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleResponse{Result: bundle})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals/") {
			cellID, snapshotID, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealPath(r.URL.Path, "/review-bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle(r.Context(), cellID, snapshotID, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleOptions(cellID, snapshotID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, snapshotID, err = parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealPath(r.URL.Path, "/review-bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle(r.Context(), cellID, snapshotID, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleOptions(cellID, snapshotID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleResponse{Result: bundle})
				return
			}

			cellID, snapshotID, err = parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.GetFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(r.Context(), cellID, snapshotID)
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, snapshotID, err = parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.GetFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(r.Context(), cellID, snapshotID)
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleResponse{Result: bundle})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/") {
			cellID, challengeAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/alignment-response/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle(r.Context(), cellID, challengeAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleOptions(cellID, challengeAppealID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, challengeAppealID, err = parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/alignment-response/bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle(r.Context(), cellID, challengeAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleOptions(cellID, challengeAppealID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleResponse{Result: bundle})
				return
			}

			cellID, challengeAppealID, err = parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle(r.Context(), cellID, challengeAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleOptions(cellID, challengeAppealID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, challengeAppealID, err = parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle(r.Context(), cellID, challengeAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleOptions(cellID, challengeAppealID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleResponse{Result: bundle})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/incident-reports/") {
			cellID, reportID, err := parseSecureCellFederationIncidentReportActionPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentReportBundle(r.Context(), cellID, reportID, secureCellFederationIncidentReportBundleOptions(cellID, reportID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentReportBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, reportID, err = parseSecureCellFederationIncidentReportActionPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentReportBundle(r.Context(), cellID, reportID, secureCellFederationIncidentReportBundleOptions(cellID, reportID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportBundleResponse{Result: bundle})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/incident-report-amendments/") {
			cellID, amendmentID, err := parseSecureCellFederationIncidentReportAmendmentActionPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentReportAmendmentBundle(r.Context(), cellID, amendmentID, secureCellFederationIncidentReportAmendmentBundleOptions(cellID, amendmentID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentReportAmendmentBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, amendmentID, err = parseSecureCellFederationIncidentReportAmendmentActionPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentReportAmendmentBundle(r.Context(), cellID, amendmentID, secureCellFederationIncidentReportAmendmentBundleOptions(cellID, amendmentID))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentBundleResponse{Result: bundle})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/incident-report-reconciliations/") {
			cellID, comparisonKey, err := parseSecureCellFederationIncidentReportReconciliationActionPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentReportReconciliationBundle(r.Context(), cellID, comparisonKey, secureCellFederationIncidentReportReconciliationBundleOptions(cellID, comparisonKey))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentReportReconciliationBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, comparisonKey, err = parseSecureCellFederationIncidentReportReconciliationActionPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentReportReconciliationBundle(r.Context(), cellID, comparisonKey, secureCellFederationIncidentReportReconciliationBundleOptions(cellID, comparisonKey))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportReconciliationBundleResponse{Result: bundle})
				return
			}
		}

		if strings.Contains(r.URL.Path, "/federation/incident-report-amendment-reconciliations/") {
			cellID, comparisonKey, err := parseSecureCellFederationIncidentReportAmendmentReconciliationActionPath(r.URL.Path, "/bundle/export")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentReportAmendmentReconciliationBundle(r.Context(), cellID, comparisonKey, secureCellFederationIncidentReportAmendmentReconciliationBundleOptions(cellID, comparisonKey))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				if err := writeSecureCellFederationIncidentReportAmendmentReconciliationBundleExport(w, r, bundle); err != nil {
					writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				}
				return
			}

			cellID, comparisonKey, err = parseSecureCellFederationIncidentReportAmendmentReconciliationActionPath(r.URL.Path, "/bundle")
			if err == nil {
				bundle, err := app.secureCellService.BuildFederationIncidentReportAmendmentReconciliationBundle(r.Context(), cellID, comparisonKey, secureCellFederationIncidentReportAmendmentReconciliationBundleOptions(cellID, comparisonKey))
				if err != nil {
					writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
					return
				}
				writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentReportAmendmentReconciliationBundleResponse{Result: bundle})
				return
			}
		}

		if strings.HasSuffix(r.URL.Path, "/trust-pack/export") && strings.Contains(r.URL.Path, "/federation/organizations/") {
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/trust-pack/export")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			pack, err := app.secureCellService.BuildFederationOrganizationTrustPack(r.Context(), cellID, organizationID, secureCellFederationTrustPackOptions(cellID, organizationID))
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			if err := writeSecureCellFederationTrustPackExport(w, r, pack); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if strings.HasSuffix(r.URL.Path, "/assurance/export") && strings.Contains(r.URL.Path, "/federation/organizations/") {
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/assurance/export")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			report, err := app.secureCellService.BuildFederationAssuranceReport(r.Context(), cellID, organizationID, secureCellFederationAssuranceReportOptions(cellID, organizationID))
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			if err := writeSecureCellFederationAssuranceReportExport(w, r, report); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if strings.HasSuffix(r.URL.Path, "/assurance/bundle/export") && strings.Contains(r.URL.Path, "/federation/organizations/") {
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/assurance/bundle/export")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			bundle, err := app.secureCellService.BuildFederationAssuranceBundle(r.Context(), cellID, organizationID, secureCellFederationAssuranceBundleOptions(cellID, organizationID))
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			if err := writeSecureCellFederationAssuranceBundleExport(w, r, bundle); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if strings.HasSuffix(r.URL.Path, "/incident-bulletin/export") && strings.Contains(r.URL.Path, "/federation/organizations/") {
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/incident-bulletin/export")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			bulletin, err := app.secureCellService.BuildFederationIncidentBulletin(r.Context(), cellID, organizationID, secureCellFederationIncidentBulletinOptions(cellID, organizationID))
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			if err := writeSecureCellFederationIncidentBulletinExport(w, r, bulletin); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if strings.HasSuffix(r.URL.Path, "/assurance/bundle") && strings.Contains(r.URL.Path, "/federation/organizations/") {
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/assurance/bundle")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			bundle, err := app.secureCellService.BuildFederationAssuranceBundle(r.Context(), cellID, organizationID, secureCellFederationAssuranceBundleOptions(cellID, organizationID))
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationAssuranceBundleResponse{Result: bundle})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/incident-bulletin") && strings.Contains(r.URL.Path, "/federation/organizations/") {
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/incident-bulletin")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			bulletin, err := app.secureCellService.BuildFederationIncidentBulletin(r.Context(), cellID, organizationID, secureCellFederationIncidentBulletinOptions(cellID, organizationID))
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationIncidentBulletinResponse{Result: bulletin})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/assurance") && strings.Contains(r.URL.Path, "/federation/organizations/") {
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/assurance")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			report, err := app.secureCellService.BuildFederationAssuranceReport(r.Context(), cellID, organizationID, secureCellFederationAssuranceReportOptions(cellID, organizationID))
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationAssuranceReportResponse{Result: report})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/trust-pack") && strings.Contains(r.URL.Path, "/federation/organizations/") {
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/trust-pack")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			pack, err := app.secureCellService.BuildFederationOrganizationTrustPack(r.Context(), cellID, organizationID, secureCellFederationTrustPackOptions(cellID, organizationID))
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationTrustPackResponse{Result: pack})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/bundle/export") && strings.Contains(r.URL.Path, "/federation/invitations/") {
			cellID, invitationID, err := parseSecureCellFederationInvitationActionPath(r.URL.Path, "/bundle/export")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			bundle, err := app.secureCellService.BuildFederationInvitationBundle(r.Context(), cellID, invitationID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			if err := writeSecureCellFederationInvitationBundleExport(w, r, bundle); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if strings.HasSuffix(r.URL.Path, "/bundle") && strings.Contains(r.URL.Path, "/federation/invitations/") {
			cellID, invitationID, err := parseSecureCellFederationInvitationActionPath(r.URL.Path, "/bundle")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			bundle, err := app.secureCellService.BuildFederationInvitationBundle(r.Context(), cellID, invitationID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationInvitationBundleResponse{Result: bundle})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/export") && strings.Contains(r.URL.Path, "/federation/contracts/") {
			cellID, contractID, err := parseSecureCellFederationContractActionPath(r.URL.Path, "/export")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			bundle, err := app.secureCellService.BuildFederationContractBundle(r.Context(), cellID, contractID, secureCellFederationContractBundleOptions(cellID, contractID))
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			if err := writeSecureCellFederationContractBundleExport(w, r, bundle); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			}
			return
		}

		if strings.Contains(r.URL.Path, "/federation/contracts/") {
			cellID, contractID, err := parseSecureCellFederationContractActionPath(r.URL.Path, "")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			bundle, err := app.secureCellService.BuildFederationContractBundle(r.Context(), cellID, contractID, secureCellFederationContractBundleOptions(cellID, contractID))
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationContractBundleResponse{Result: bundle})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/federation") {
			cellID, err := parseSecureCellID(r.URL.Path, "/federation")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellFederationProjection(result))
			return
		}

		if strings.HasSuffix(r.URL.Path, "/decisions") && strings.Contains(r.URL.Path, "/threads/") {
			cellID, sessionID, threadID, err := parseSecureCellSessionThreadActionPath(r.URL.Path, "/decisions")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellDecisionListResponse{Items: secureCellDecisionsForThread(result, sessionID, threadID)})
			return
		}

		if strings.HasSuffix(r.URL.Path, "/artifacts") {
			cellID, err := parseSecureCellID(r.URL.Path, "/artifacts")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellArtifactsProjection(result))
			return
		}

		cellID, err := parseSecureCellID(r.URL.Path, "")
		if err != nil {
			writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		result, err := app.secureCellService.GetCell(r.Context(), cellID)
		if err != nil {
			writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
			return
		}
		writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
	})
}

func (app *AethelredApp) SecureCellsMutateHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeSecureCellAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.secureCellService == nil {
			writeSecureCellAPIError(w, http.StatusServiceUnavailable, "secure cell service is unavailable")
			return
		}

		switch {
		case strings.HasSuffix(r.URL.Path, "/federation/invitations"):
			cellID, err := parseSecureCellID(r.URL.Path, "/federation/invitations")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationInviteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation invitation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationInvite(r, cellID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.CreateFederationInvitation(r.Context(), cellID, securecellsintegration.SecureCellFederationInviteRequest{
				ActorDID:                            safeSecureCellActorDID(authCtx),
				SponsorOfRecord:                     req.SponsorOfRecord,
				OrganizationName:                    req.OrganizationName,
				Jurisdiction:                        req.Jurisdiction,
				ExpectedDID:                         req.ExpectedDID,
				Role:                                req.Role,
				SessionScopeIDs:                     append([]string(nil), req.SessionScopeIDs...),
				DataClasses:                         append([]string(nil), req.DataClasses...),
				ComputeZones:                        append([]string(nil), req.ComputeZones...),
				AllowedActions:                      append([]string(nil), req.AllowedActions...),
				CounterproposalGovernanceTemplate:   req.CounterproposalGovernanceTemplate,
				CounterproposalApprovalThreshold:    cast.ToInt(req.CounterproposalApprovalThreshold),
				CounterproposalEligibleApproverDIDs: append([]string(nil), req.CounterproposalEligibleApproverDIDs...),
				CounterproposalEscalationLadder:     append([]securecellsintegration.SecureCellFederationEscalationTier(nil), req.CounterproposalEscalationLadder...),
				CounterproposalResolutionDueAt:      safeSecureCellOptionalTime(req.CounterproposalResolutionDueAt),
				CounterproposalAutoSuspendOnOverdue: req.CounterproposalAutoSuspendOnOverdue != nil && *req.CounterproposalAutoSuspendOnOverdue,
				Resource:                            req.Resource,
				Reason:                              req.Reason,
				Metadata:                            req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/accept") && strings.Contains(r.URL.Path, "/federation/invitations/"):
			cellID, invitationID, err := parseSecureCellFederationInvitationActionPath(r.URL.Path, "/accept")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationAcceptRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation acceptance request: "+err.Error())
				return
			}
			req.InvitationID = firstNonEmpty(req.InvitationID, invitationID)
			authCtx, err := app.authorizeSecureCellFederationAccept(r, cellID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcceptFederationInvitation(r.Context(), cellID, securecellsintegration.SecureCellFederationAcceptRequest{
				InvitationID:           req.InvitationID,
				ActorDID:               safeSecureCellActorDID(authCtx),
				Participant:            req.Participant,
				OfferedSessionScopeIDs: append([]string(nil), req.OfferedSessionScopeIDs...),
				OfferedDataClasses:     append([]string(nil), req.OfferedDataClasses...),
				OfferedComputeZones:    append([]string(nil), req.OfferedComputeZones...),
				OfferedActions:         append([]string(nil), req.OfferedActions...),
				Reason:                 req.Reason,
				Metadata:               req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/counterproposals") && strings.Contains(r.URL.Path, "/federation/invitations/"):
			cellID, invitationID, err := parseSecureCellFederationInvitationActionPath(r.URL.Path, "/counterproposals")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationCounterproposalRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation counterproposal request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationCounterproposalSubmit(r, cellID, invitationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.SubmitFederationCounterproposal(r.Context(), cellID, invitationID, securecellsintegration.SecureCellFederationCounterproposalRequest{
				ActorDID:               safeSecureCellActorDID(authCtx),
				OfferedSessionScopeIDs: append([]string(nil), req.OfferedSessionScopeIDs...),
				OfferedDataClasses:     append([]string(nil), req.OfferedDataClasses...),
				OfferedComputeZones:    append([]string(nil), req.OfferedComputeZones...),
				OfferedActions:         append([]string(nil), req.OfferedActions...),
				Resource:               req.Resource,
				Reason:                 req.Reason,
				Metadata:               req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/revoke") && strings.Contains(r.URL.Path, "/federation/invitations/"):
			cellID, invitationID, err := parseSecureCellFederationInvitationActionPath(r.URL.Path, "/revoke")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation revoke request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationRevoke(r, cellID, invitationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RevokeFederationInvitation(r.Context(), cellID, invitationID, securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/assurance/intake") && strings.Contains(r.URL.Path, "/federation/organizations/"):
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/assurance/intake")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationAssuranceIntakeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation assurance intake request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationAssuranceIntake(r, cellID, organizationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.IngestFederationAssuranceBundle(r.Context(), cellID, organizationID, securecellsintegration.SecureCellFederationAssuranceIntakeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Bundle:   req.Bundle,
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/incident-bulletin/intake") && strings.Contains(r.URL.Path, "/federation/organizations/"):
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/incident-bulletin/intake")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentBulletinIntakeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident bulletin intake request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentIntake(r, cellID, organizationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.IngestFederationIncidentBulletin(r.Context(), cellID, organizationID, securecellsintegration.SecureCellFederationIncidentBulletinIntakeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Bulletin: req.Bulletin,
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/incident-report-bundles/intake") && strings.Contains(r.URL.Path, "/federation/organizations/"):
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/incident-report-bundles/intake")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportBundleIntakeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report bundle intake request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportIntake(r, cellID, organizationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.IngestFederationIncidentReportBundle(r.Context(), cellID, organizationID, securecellsintegration.SecureCellFederationIncidentReportBundleIntakeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Bundle:   req.Bundle,
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/incident-report-amendment-bundles/intake") && strings.Contains(r.URL.Path, "/federation/organizations/"):
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/incident-report-amendment-bundles/intake")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportAmendmentBundleIntakeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report amendment bundle intake request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportAmendmentIntake(r, cellID, organizationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.IngestFederationIncidentReportAmendmentBundle(r.Context(), cellID, organizationID, securecellsintegration.SecureCellFederationIncidentReportAmendmentBundleIntakeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Bundle:   req.Bundle,
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/incident-directive-extension-appeal-bundles/intake") && strings.Contains(r.URL.Path, "/federation/organizations/"):
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/incident-directive-extension-appeal-bundles/intake")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealBundleIntakeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal bundle intake request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealIntake(r, cellID, organizationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.IngestFederationIncidentDirectiveExtensionAppealBundle(r.Context(), cellID, organizationID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealBundleIntakeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Bundle:   req.Bundle,
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/incidents") && strings.Contains(r.URL.Path, "/federation/organizations/"):
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/incidents")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentPublishRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident publish request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentPublish(r, cellID, organizationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.PublishFederationIncident(r.Context(), cellID, organizationID, securecellsintegration.SecureCellFederationIncidentPublishRequest{
				ActorDID:                 safeSecureCellActorDID(authCtx),
				Severity:                 req.Severity,
				Category:                 req.Category,
				Summary:                  req.Summary,
				Description:              req.Description,
				ContractIDs:              append([]string(nil), req.ContractIDs...),
				SessionIDs:               append([]string(nil), req.SessionIDs...),
				ThreadIDs:                append([]string(nil), req.ThreadIDs...),
				SharedOutputIDs:          append([]string(nil), req.SharedOutputIDs...),
				SessionExchangeIDs:       append([]string(nil), req.SessionExchangeIDs...),
				AutoContainmentRequested: req.AutoContainmentRequested != nil && *req.AutoContainmentRequested,
				ExpiresAt:                safeSecureCellOptionalTime(req.ExpiresAt),
				Reason:                   req.Reason,
				Metadata:                 req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/resolve") && strings.Contains(r.URL.Path, "/federation/organizations/") && strings.Contains(r.URL.Path, "/incidents/"):
			cellID, organizationID, incidentID, err := parseSecureCellFederationIncidentActionPath(r.URL.Path, "/resolve")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentResolveRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident resolve request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentResolve(r, cellID, organizationID, incidentID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.ResolveFederationIncident(r.Context(), cellID, organizationID, incidentID, securecellsintegration.SecureCellFederationIncidentResolveRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/incident-directive-extension-appeal-reconciliation-challenge-appeal-bundles/intake") && strings.Contains(r.URL.Path, "/federation/organizations/"):
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/incident-directive-extension-appeal-reconciliation-challenge-appeal-bundles/intake")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleIntakeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal bundle intake request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealIntake(r, cellID, organizationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.IngestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle(r.Context(), cellID, organizationID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleIntakeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Bundle:   req.Bundle,
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundles/intake") && strings.Contains(r.URL.Path, "/federation/organizations/"):
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundles/intake")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleIntakeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response bundle intake request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseIntake(r, cellID, organizationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.IngestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle(r.Context(), cellID, organizationID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleIntakeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Bundle:   req.Bundle,
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundles/intake") && strings.Contains(r.URL.Path, "/federation/organizations/"):
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundles/intake")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleIntakeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal bundle intake request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealIntake(r, cellID, organizationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.IngestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(r.Context(), cellID, organizationID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleIntakeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Bundle:   req.Bundle,
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundles/intake") && strings.Contains(r.URL.Path, "/federation/organizations/"):
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundles/intake")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleIntakeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal bundle intake request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealIntake(r, cellID, organizationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.IngestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundle(r.Context(), cellID, organizationID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleIntakeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Bundle:   req.Bundle,
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundles/intake") && strings.Contains(r.URL.Path, "/federation/organizations/"):
			cellID, organizationID, err := parseSecureCellFederationOrganizationActionPath(r.URL.Path, "/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundles/intake")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleIntakeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal review bundle intake request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleIntake(r, cellID, organizationID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.IngestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundle(r.Context(), cellID, organizationID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleIntakeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Bundle:   req.Bundle,
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/reports") && strings.Contains(r.URL.Path, "/federation/incident-responses/"):
			cellID, responseID, err := parseSecureCellFederationIncidentResponseActionPath(r.URL.Path, "/reports")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportPlanRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report plan request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportPlan(r, cellID, responseID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.CreateFederationIncidentReport(r.Context(), cellID, responseID, securecellsintegration.SecureCellFederationIncidentReportPlanRequest{
				ActorDID:         safeSecureCellActorDID(authCtx),
				ReportingParty:   req.ReportingParty,
				Regulator:        req.Regulator,
				Jurisdiction:     req.Jurisdiction,
				Framework:        req.Framework,
				ReportType:       req.ReportType,
				Summary:          req.Summary,
				Description:      req.Description,
				RequiredSections: append([]string(nil), req.RequiredSections...),
				EvidenceIDs:      append([]string(nil), req.EvidenceIDs...),
				DueAt:            req.DueAt,
				Reason:           req.Reason,
				Metadata:         req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/directives") && strings.Contains(r.URL.Path, "/federation/incident-responses/"):
			cellID, responseID, err := parseSecureCellFederationIncidentResponseActionPath(r.URL.Path, "/directives")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveCreateRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive create request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveIssue(r, cellID, responseID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.CreateFederationIncidentDirective(r.Context(), cellID, responseID, securecellsintegration.SecureCellFederationIncidentDirectiveCreateRequest{
				ActorDID:            safeSecureCellActorDID(authCtx),
				DirectiveType:       req.DirectiveType,
				Title:               req.Title,
				Summary:             req.Summary,
				Description:         req.Description,
				Priority:            req.Priority,
				AssigneeParty:       req.AssigneeParty,
				ReviewerParty:       req.ReviewerParty,
				AssigneeDID:         req.AssigneeDID,
				ReviewerDID:         req.ReviewerDID,
				RelatedReportIDs:    append([]string(nil), req.RelatedReportIDs...),
				RelatedAmendmentIDs: append([]string(nil), req.RelatedAmendmentIDs...),
				EvidenceIDs:         append([]string(nil), req.EvidenceIDs...),
				DueAt:               req.DueAt,
				Reason:              req.Reason,
				Metadata:            req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/extensions") && strings.Contains(r.URL.Path, "/federation/incident-directives/"):
			cellID, directiveID, err := parseSecureCellFederationIncidentDirectiveActionPath(r.URL.Path, "/extensions")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionRequest(r, cellID, directiveID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RequestFederationIncidentDirectiveExtension(r.Context(), cellID, directiveID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionRequest{
				ActorDID:                   safeSecureCellActorDID(authCtx),
				RequestingParty:            req.RequestingParty,
				Summary:                    req.Summary,
				Description:                req.Description,
				EvidenceIDs:                append([]string(nil), req.EvidenceIDs...),
				ProposedDueAt:              req.ProposedDueAt,
				ReviewApprovalThreshold:    req.ReviewApprovalThreshold,
				EligibleReviewerDIDs:       append([]string(nil), req.EligibleReviewerDIDs...),
				DisputeResolutionThreshold: req.DisputeResolutionThreshold,
				EligibleResolverDIDs:       append([]string(nil), req.EligibleResolverDIDs...),
				Reason:                     req.Reason,
				Metadata:                   req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge") && strings.Contains(r.URL.Path, "/federation/incident-responses/"):
			cellID, responseID, err := parseSecureCellFederationIncidentResponseActionPath(r.URL.Path, "/acknowledge")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentResponseAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident response acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentResponseAcknowledge(r, cellID, responseID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentResponse(r.Context(), cellID, responseID, securecellsintegration.SecureCellFederationIncidentResponseAcknowledgeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge") && strings.Contains(r.URL.Path, "/federation/incident-directives/"):
			cellID, directiveID, err := parseSecureCellFederationIncidentDirectiveActionPath(r.URL.Path, "/acknowledge")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveAcknowledge(r, cellID, directiveID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentDirective(r.Context(), cellID, directiveID, securecellsintegration.SecureCellFederationIncidentDirectiveAcknowledgeRequest{
				ActorDID:           safeSecureCellActorDID(authCtx),
				AcknowledgingParty: req.AcknowledgingParty,
				Reason:             req.Reason,
				Metadata:           req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/escalate") && strings.Contains(r.URL.Path, "/federation/incident-responses/"):
			cellID, responseID, err := parseSecureCellFederationIncidentResponseActionPath(r.URL.Path, "/escalate")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentResponseEscalateRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident response escalate request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentResponseEscalate(r, cellID, responseID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.EscalateFederationIncidentResponse(r.Context(), cellID, responseID, securecellsintegration.SecureCellFederationIncidentResponseEscalateRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				TierID:   req.TierID,
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/complete") && strings.Contains(r.URL.Path, "/federation/incident-directives/"):
			cellID, directiveID, err := parseSecureCellFederationIncidentDirectiveActionPath(r.URL.Path, "/complete")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveCompleteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive complete request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveComplete(r, cellID, directiveID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.CompleteFederationIncidentDirective(r.Context(), cellID, directiveID, securecellsintegration.SecureCellFederationIncidentDirectiveCompleteRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				CompletingParty:       req.CompletingParty,
				CompletionSummary:     req.CompletionSummary,
				CompletionDescription: req.CompletionDescription,
				EvidenceIDs:           append([]string(nil), req.EvidenceIDs...),
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/remediations") && strings.Contains(r.URL.Path, "/federation/incident-responses/"):
			cellID, responseID, err := parseSecureCellFederationIncidentResponseActionPath(r.URL.Path, "/remediations")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentRemediationAttestationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident remediation attestation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentRemediationAttest(r, cellID, responseID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AttestFederationIncidentRemediation(r.Context(), cellID, responseID, securecellsintegration.SecureCellFederationIncidentRemediationAttestationRequest{
				ActorDID:       safeSecureCellActorDID(authCtx),
				AttestingParty: req.AttestingParty,
				Summary:        req.Summary,
				Description:    req.Description,
				EvidenceIDs:    append([]string(nil), req.EvidenceIDs...),
				Reason:         req.Reason,
				Metadata:       req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/verify") && strings.Contains(r.URL.Path, "/federation/incident-directives/"):
			cellID, directiveID, err := parseSecureCellFederationIncidentDirectiveActionPath(r.URL.Path, "/verify")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveVerifyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive verify request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveVerify(r, cellID, directiveID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.VerifyFederationIncidentDirective(r.Context(), cellID, directiveID, securecellsintegration.SecureCellFederationIncidentDirectiveVerifyRequest{
				ActorDID:                safeSecureCellActorDID(authCtx),
				ReviewingParty:          req.ReviewingParty,
				Decision:                req.Decision,
				VerificationSummary:     req.VerificationSummary,
				VerificationDescription: req.VerificationDescription,
				EvidenceIDs:             append([]string(nil), req.EvidenceIDs...),
				Reason:                  req.Reason,
				Metadata:                req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/approve") && strings.Contains(r.URL.Path, "/federation/incident-directive-extensions/"):
			cellID, extensionID, err := parseSecureCellFederationIncidentDirectiveExtensionActionPath(r.URL.Path, "/approve")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionApproveRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension approve request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionApprove(r, cellID, extensionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.ApproveFederationIncidentDirectiveExtension(r.Context(), cellID, extensionID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionApproveRequest{
				ActorDID:            safeSecureCellActorDID(authCtx),
				ReviewingParty:      req.ReviewingParty,
				DecisionSummary:     req.DecisionSummary,
				DecisionDescription: req.DecisionDescription,
				EvidenceIDs:         append([]string(nil), req.EvidenceIDs...),
				Reason:              req.Reason,
				Metadata:            req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/delegate-review") && strings.Contains(r.URL.Path, "/federation/incident-directive-extensions/"):
			cellID, extensionID, err := parseSecureCellFederationIncidentDirectiveExtensionActionPath(r.URL.Path, "/delegate-review")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionDelegationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension review delegation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionDelegateReview(r, cellID, extensionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DelegateFederationIncidentDirectiveExtensionReview(r.Context(), cellID, extensionID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionDelegationRequest{
				ActorDID:  safeSecureCellActorDID(authCtx),
				TargetDID: req.TargetDID,
				Reason:    req.Reason,
				Metadata:  req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/reject") && strings.Contains(r.URL.Path, "/federation/incident-directive-extensions/"):
			cellID, extensionID, err := parseSecureCellFederationIncidentDirectiveExtensionActionPath(r.URL.Path, "/reject")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionRejectRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension reject request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionReject(r, cellID, extensionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RejectFederationIncidentDirectiveExtension(r.Context(), cellID, extensionID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionRejectRequest{
				ActorDID:            safeSecureCellActorDID(authCtx),
				ReviewingParty:      req.ReviewingParty,
				DecisionSummary:     req.DecisionSummary,
				DecisionDescription: req.DecisionDescription,
				EvidenceIDs:         append([]string(nil), req.EvidenceIDs...),
				Reason:              req.Reason,
				Metadata:            req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/dispute") && strings.Contains(r.URL.Path, "/federation/incident-directive-extensions/"):
			cellID, extensionID, err := parseSecureCellFederationIncidentDirectiveExtensionActionPath(r.URL.Path, "/dispute")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionDisputeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension dispute request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionDispute(r, cellID, extensionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DisputeFederationIncidentDirectiveExtension(r.Context(), cellID, extensionID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionDisputeRequest{
				ActorDID:         safeSecureCellActorDID(authCtx),
				ChallengingParty: req.ChallengingParty,
				Summary:          req.Summary,
				Description:      req.Description,
				EvidenceIDs:      append([]string(nil), req.EvidenceIDs...),
				Reason:           req.Reason,
				Metadata:         req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/resolve") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-disputes/"):
			cellID, disputeID, err := parseSecureCellFederationIncidentDirectiveExtensionDisputeActionPath(r.URL.Path, "/resolve")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionDisputeResolveRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension dispute resolve request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionResolve(r, cellID, disputeID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.ResolveFederationIncidentDirectiveExtensionDispute(r.Context(), cellID, disputeID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionDisputeResolveRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				RespondingParty:       req.RespondingParty,
				Resolution:            req.Resolution,
				ResolutionSummary:     req.ResolutionSummary,
				ResolutionDescription: req.ResolutionDescription,
				EvidenceIDs:           append([]string(nil), req.EvidenceIDs...),
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/delegate-resolution") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-disputes/"):
			cellID, disputeID, err := parseSecureCellFederationIncidentDirectiveExtensionDisputeActionPath(r.URL.Path, "/delegate-resolution")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionDelegationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension dispute delegation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionDelegateResolution(r, cellID, disputeID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DelegateFederationIncidentDirectiveExtensionDisputeResolution(r.Context(), cellID, disputeID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionDelegationRequest{
				ActorDID:  safeSecureCellActorDID(authCtx),
				TargetDID: req.TargetDID,
				Reason:    req.Reason,
				Metadata:  req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/appeal") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-disputes/"):
			cellID, disputeID, err := parseSecureCellFederationIncidentDirectiveExtensionDisputeActionPath(r.URL.Path, "/appeal")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppeal(r, cellID, disputeID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AppealFederationIncidentDirectiveExtensionDispute(r.Context(), cellID, disputeID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealRequest{
				ActorDID:                  safeSecureCellActorDID(authCtx),
				AppealingParty:            req.AppealingParty,
				Summary:                   req.Summary,
				Description:               req.Description,
				EvidenceIDs:               append([]string(nil), req.EvidenceIDs...),
				BoardReviewThreshold:      req.BoardReviewThreshold,
				EligibleBoardReviewerDIDs: append([]string(nil), req.EligibleBoardReviewerDIDs...),
				Reason:                    req.Reason,
				Metadata:                  req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/rule") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeals/"):
			cellID, appealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealActionPath(r.URL.Path, "/rule")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealRulingRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal ruling request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealRule(r, cellID, appealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RuleFederationIncidentDirectiveExtensionAppeal(r.Context(), cellID, appealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealRulingRequest{
				ActorDID:          safeSecureCellActorDID(authCtx),
				BoardParty:        req.BoardParty,
				Ruling:            req.Ruling,
				RulingSummary:     req.RulingSummary,
				RulingDescription: req.RulingDescription,
				EvidenceIDs:       append([]string(nil), req.EvidenceIDs...),
				Reason:            req.Reason,
				Metadata:          req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/delegate-review") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeals/"):
			cellID, appealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealActionPath(r.URL.Path, "/delegate-review")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionDelegationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal delegation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealDelegateReview(r, cellID, appealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DelegateFederationIncidentDirectiveExtensionAppealReview(r.Context(), cellID, appealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionDelegationRequest{
				ActorDID:  safeSecureCellActorDID(authCtx),
				TargetDID: req.TargetDID,
				Reason:    req.Reason,
				Metadata:  req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/recuse") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeals/"):
			cellID, appealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealActionPath(r.URL.Path, "/recuse")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealRecuseRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal recusal request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealRecuse(r, cellID, appealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RecuseFederationIncidentDirectiveExtensionAppealReview(r.Context(), cellID, appealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealRecuseRequest{
				ActorDID:    safeSecureCellActorDID(authCtx),
				BoardParty:  req.BoardParty,
				Summary:     req.Summary,
				Description: req.Description,
				EvidenceIDs: append([]string(nil), req.EvidenceIDs...),
				Reason:      req.Reason,
				Metadata:    req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/rehear") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeals/"):
			cellID, appealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealActionPath(r.URL.Path, "/rehear")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealRehearingRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal rehearing request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealRehear(r, cellID, appealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RehearFederationIncidentDirectiveExtensionAppeal(r.Context(), cellID, appealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealRehearingRequest{
				ActorDID:                  safeSecureCellActorDID(authCtx),
				AppealingParty:            req.AppealingParty,
				Summary:                   req.Summary,
				Description:               req.Description,
				EvidenceIDs:               append([]string(nil), req.EvidenceIDs...),
				BoardReviewThreshold:      req.BoardReviewThreshold,
				EligibleBoardReviewerDIDs: append([]string(nil), req.EligibleBoardReviewerDIDs...),
				Reason:                    req.Reason,
				Metadata:                  req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge-enforcement") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeals/"):
			cellID, appealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealActionPath(r.URL.Path, "/acknowledge-enforcement")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealAcknowledge(r, cellID, appealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentDirectiveExtensionAppealEnforcement(r.Context(), cellID, appealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealAcknowledgeRequest{
				ActorDID:           safeSecureCellActorDID(authCtx),
				AcknowledgingParty: req.AcknowledgingParty,
				Summary:            req.Summary,
				Description:        req.Description,
				EvidenceIDs:        append([]string(nil), req.EvidenceIDs...),
				Reason:             req.Reason,
				Metadata:           req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/verify-remediation") && strings.Contains(r.URL.Path, "/federation/incident-responses/"):
			cellID, responseID, err := parseSecureCellFederationIncidentResponseActionPath(r.URL.Path, "/verify-remediation")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentRemediationVerificationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident remediation verification request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentRemediationVerify(r, cellID, responseID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.VerifyFederationIncidentRemediation(r.Context(), cellID, responseID, securecellsintegration.SecureCellFederationIncidentRemediationVerificationRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				ReviewingParty:        req.ReviewingParty,
				Decision:              req.Decision,
				VerifiedAttestationID: req.VerifiedAttestationID,
				Summary:               req.Summary,
				Description:           req.Description,
				EvidenceIDs:           append([]string(nil), req.EvidenceIDs...),
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/attest-closure") && strings.Contains(r.URL.Path, "/federation/incident-responses/"):
			cellID, responseID, err := parseSecureCellFederationIncidentResponseActionPath(r.URL.Path, "/attest-closure")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentClosureAttestationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident closure attestation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentClosureAttest(r, cellID, responseID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AttestFederationIncidentClosure(r.Context(), cellID, responseID, securecellsintegration.SecureCellFederationIncidentClosureAttestationRequest{
				ActorDID:       safeSecureCellActorDID(authCtx),
				AttestingParty: req.AttestingParty,
				Summary:        req.Summary,
				Description:    req.Description,
				EvidenceIDs:    append([]string(nil), req.EvidenceIDs...),
				Reason:         req.Reason,
				Metadata:       req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/dispute") && strings.Contains(r.URL.Path, "/federation/incident-responses/"):
			cellID, responseID, err := parseSecureCellFederationIncidentResponseActionPath(r.URL.Path, "/dispute")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentResponseDisputeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident response dispute request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentResponseDispute(r, cellID, responseID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DisputeFederationIncidentResponse(r.Context(), cellID, responseID, securecellsintegration.SecureCellFederationIncidentResponseDisputeRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				DisputingParty:        req.DisputingParty,
				RelatedVerificationID: req.RelatedVerificationID,
				RelatedClosureID:      req.RelatedClosureID,
				Summary:               req.Summary,
				Description:           req.Description,
				EvidenceIDs:           append([]string(nil), req.EvidenceIDs...),
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/submit") && strings.Contains(r.URL.Path, "/federation/incident-reports/"):
			cellID, reportID, err := parseSecureCellFederationIncidentReportActionPath(r.URL.Path, "/submit")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportSubmitRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report submit request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportSubmit(r, cellID, reportID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.SubmitFederationIncidentReport(r.Context(), cellID, reportID, securecellsintegration.SecureCellFederationIncidentReportSubmitRequest{
				ActorDID:            safeSecureCellActorDID(authCtx),
				SubmissionReference: req.SubmissionReference,
				Summary:             req.Summary,
				Description:         req.Description,
				EvidenceIDs:         append([]string(nil), req.EvidenceIDs...),
				Reason:              req.Reason,
				Metadata:            req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/amend") && strings.Contains(r.URL.Path, "/federation/incident-reports/"):
			cellID, reportID, err := parseSecureCellFederationIncidentReportActionPath(r.URL.Path, "/amend")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportAmendRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report amend request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportAmend(r, cellID, reportID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AmendFederationIncidentReport(r.Context(), cellID, reportID, securecellsintegration.SecureCellFederationIncidentReportAmendRequest{
				ActorDID:        safeSecureCellActorDID(authCtx),
				Summary:         req.Summary,
				Description:     req.Description,
				ChangedSections: append([]string(nil), req.ChangedSections...),
				EvidenceIDs:     append([]string(nil), req.EvidenceIDs...),
				Reason:          req.Reason,
				Metadata:        req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge") && strings.Contains(r.URL.Path, "/federation/incident-reports/"):
			cellID, reportID, err := parseSecureCellFederationIncidentReportActionPath(r.URL.Path, "/acknowledge")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportAcknowledge(r, cellID, reportID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentReport(r.Context(), cellID, reportID, securecellsintegration.SecureCellFederationIncidentReportAcknowledgeRequest{
				ActorDID:                 safeSecureCellActorDID(authCtx),
				AcknowledgingParty:       req.AcknowledgingParty,
				AcknowledgementReference: req.AcknowledgementReference,
				Reason:                   req.Reason,
				Metadata:                 req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/submit") && strings.Contains(r.URL.Path, "/federation/incident-report-amendments/"):
			cellID, amendmentID, err := parseSecureCellFederationIncidentReportAmendmentActionPath(r.URL.Path, "/submit")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportAmendmentSubmitRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report amendment submit request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportAmendmentSubmit(r, cellID, amendmentID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.SubmitFederationIncidentReportAmendment(r.Context(), cellID, amendmentID, securecellsintegration.SecureCellFederationIncidentReportAmendmentSubmitRequest{
				ActorDID:            safeSecureCellActorDID(authCtx),
				SubmissionReference: req.SubmissionReference,
				Summary:             req.Summary,
				Description:         req.Description,
				EvidenceIDs:         append([]string(nil), req.EvidenceIDs...),
				Reason:              req.Reason,
				Metadata:            req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge") && strings.Contains(r.URL.Path, "/federation/incident-report-amendments/"):
			cellID, amendmentID, err := parseSecureCellFederationIncidentReportAmendmentActionPath(r.URL.Path, "/acknowledge")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportAmendmentAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report amendment acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportAmendmentAcknowledge(r, cellID, amendmentID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentReportAmendment(r.Context(), cellID, amendmentID, securecellsintegration.SecureCellFederationIncidentReportAmendmentAcknowledgeRequest{
				ActorDID:                 safeSecureCellActorDID(authCtx),
				AcknowledgingParty:       req.AcknowledgingParty,
				AcknowledgementReference: req.AcknowledgementReference,
				Reason:                   req.Reason,
				Metadata:                 req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionPath(r.URL.Path, "/acknowledge")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationAcknowledge(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliation(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAcknowledgeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/dispute") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionPath(r.URL.Path, "/dispute")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationDisputeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation dispute request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationDispute(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DisputeFederationIncidentDirectiveExtensionAppealReconciliation(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationDisputeRequest{
				ActorDID:    safeSecureCellActorDID(authCtx),
				Reason:      req.Reason,
				Divergences: append([]string(nil), req.Divergences...),
				Metadata:    req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/resolve") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionPath(r.URL.Path, "/resolve")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolveRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation resolve request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolve(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.ResolveFederationIncidentDirectiveExtensionAppealReconciliation(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolveRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/challenge") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionPath(r.URL.Path, "/challenge")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallenge(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.ChallengeFederationIncidentDirectiveExtensionAppealReconciliation(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRequest{
				ActorDID:                  safeSecureCellActorDID(authCtx),
				ChallengingParty:          req.ChallengingParty,
				Summary:                   req.Summary,
				Description:               req.Description,
				EvidenceIDs:               append([]string(nil), req.EvidenceIDs...),
				BoardReviewThreshold:      req.BoardReviewThreshold,
				EligibleBoardReviewerDIDs: append([]string(nil), req.EligibleBoardReviewerDIDs...),
				Reason:                    req.Reason,
				Metadata:                  req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/rule") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionPath(r.URL.Path, "/rule")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRulingRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation rule request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationRule(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RuleFederationIncidentDirectiveExtensionAppealReconciliation(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRulingRequest{
				ActorDID:          safeSecureCellActorDID(authCtx),
				BoardParty:        req.BoardParty,
				Ruling:            req.Ruling,
				RulingSummary:     req.RulingSummary,
				RulingDescription: req.RulingDescription,
				EvidenceIDs:       append([]string(nil), req.EvidenceIDs...),
				Reason:            req.Reason,
				Metadata:          req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/appeals") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionPath(r.URL.Path, "/appeals")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AppealFederationIncidentDirectiveExtensionAppealReconciliationChallenge(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRequest{
				ActorDID:                  safeSecureCellActorDID(authCtx),
				AppealingParty:            req.AppealingParty,
				Summary:                   req.Summary,
				Description:               req.Description,
				EvidenceIDs:               append([]string(nil), req.EvidenceIDs...),
				BoardReviewThreshold:      req.BoardReviewThreshold,
				EligibleBoardReviewerDIDs: append([]string(nil), req.EligibleBoardReviewerDIDs...),
				Reason:                    req.Reason,
				Metadata:                  req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/alignment-response-appeals") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/alignment-response-appeals")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeal(r, cellID, challengeAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AppealFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponse(r.Context(), cellID, challengeAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRequest{
				ActorDID:                            safeSecureCellActorDID(authCtx),
				AppealingParty:                      req.AppealingParty,
				CorrectionBoardParty:                req.CorrectionBoardParty,
				EnforcementAcknowledgementParty:     req.EnforcementAcknowledgementParty,
				Summary:                             req.Summary,
				Description:                         req.Description,
				EvidenceIDs:                         append([]string(nil), req.EvidenceIDs...),
				CorrectionBoardReviewThreshold:      req.CorrectionBoardReviewThreshold,
				EligibleCorrectionBoardReviewerDIDs: append([]string(nil), req.EligibleCorrectionBoardReviewerDIDs...),
				Reason:                              req.Reason,
				Metadata:                            req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/alignment-response-appeals/") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal path")
			return
		case strings.HasSuffix(r.URL.Path, "/rule") && strings.Contains(r.URL.Path, "/alignment-response-appeals/") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, responseAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionPath(r.URL.Path, "/rule")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRulingRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal rule request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRule(r, cellID, challengeAppealID, responseAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RuleFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeal(r.Context(), cellID, responseAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRulingRequest{
				ActorDID:             safeSecureCellActorDID(authCtx),
				CorrectionBoardParty: req.CorrectionBoardParty,
				Ruling:               req.Ruling,
				RulingSummary:        req.RulingSummary,
				RulingDescription:    req.RulingDescription,
				EvidenceIDs:          append([]string(nil), req.EvidenceIDs...),
				Reason:               req.Reason,
				Metadata:             req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/delegate-review") && strings.Contains(r.URL.Path, "/alignment-response-appeals/") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, responseAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionPath(r.URL.Path, "/delegate-review")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionDelegationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal delegation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDelegateReview(r, cellID, challengeAppealID, responseAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DelegateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealReview(r.Context(), cellID, responseAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionDelegationRequest{
				ActorDID:  safeSecureCellActorDID(authCtx),
				TargetDID: req.TargetDID,
				Reason:    req.Reason,
				Metadata:  req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/recuse") && strings.Contains(r.URL.Path, "/alignment-response-appeals/") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, responseAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionPath(r.URL.Path, "/recuse")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuseRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal recuse request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuse(r, cellID, challengeAppealID, responseAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RecuseFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealReview(r.Context(), cellID, responseAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuseRequest{
				ActorDID:             safeSecureCellActorDID(authCtx),
				CorrectionBoardParty: req.CorrectionBoardParty,
				Summary:              req.Summary,
				Description:          req.Description,
				EvidenceIDs:          append([]string(nil), req.EvidenceIDs...),
				Reason:               req.Reason,
				Metadata:             req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/rehear") && strings.Contains(r.URL.Path, "/alignment-response-appeals/") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, responseAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionPath(r.URL.Path, "/rehear")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehearingRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal rehearing request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehear(r, cellID, challengeAppealID, responseAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RehearFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeal(r.Context(), cellID, responseAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehearingRequest{
				ActorDID:                            safeSecureCellActorDID(authCtx),
				AppealingParty:                      req.AppealingParty,
				CorrectionBoardParty:                req.CorrectionBoardParty,
				EnforcementAcknowledgementParty:     req.EnforcementAcknowledgementParty,
				Summary:                             req.Summary,
				Description:                         req.Description,
				EvidenceIDs:                         append([]string(nil), req.EvidenceIDs...),
				CorrectionBoardReviewThreshold:      req.CorrectionBoardReviewThreshold,
				EligibleCorrectionBoardReviewerDIDs: append([]string(nil), req.EligibleCorrectionBoardReviewerDIDs...),
				Reason:                              req.Reason,
				Metadata:                            req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge-enforcement") && strings.Contains(r.URL.Path, "/alignment-response-appeals/") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, responseAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionPath(r.URL.Path, "/acknowledge-enforcement")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledge(r, cellID, challengeAppealID, responseAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealEnforcement(r.Context(), cellID, responseAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeRequest{
				ActorDID:           safeSecureCellActorDID(authCtx),
				AcknowledgingParty: req.AcknowledgingParty,
				Summary:            req.Summary,
				Description:        req.Description,
				EvidenceIDs:        append([]string(nil), req.EvidenceIDs...),
				Reason:             req.Reason,
				Metadata:           req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge-counterparty-ruling") && strings.Contains(r.URL.Path, "/alignment-response-appeals/") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, responseAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionPath(r.URL.Path, "/acknowledge-counterparty-ruling")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeCounterparty(r, cellID, challengeAppealID, responseAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyRuling(r.Context(), cellID, responseAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyAcknowledgeRequest{
				ActorDID:                     safeSecureCellActorDID(authCtx),
				CounterpartySnapshotID:       req.CounterpartySnapshotID,
				CounterpartyResponseAppealID: req.CounterpartyResponseAppealID,
				CounterpartyReference:        req.CounterpartyReference,
				Reason:                       req.Reason,
				Metadata:                     req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/dispute-counterparty-ruling") && strings.Contains(r.URL.Path, "/alignment-response-appeals/") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, responseAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionPath(r.URL.Path, "/dispute-counterparty-ruling")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDisputeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty dispute request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDisputeCounterparty(r, cellID, challengeAppealID, responseAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DisputeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyRuling(r.Context(), cellID, responseAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDisputeRequest{
				ActorDID:                     safeSecureCellActorDID(authCtx),
				CounterpartySnapshotID:       req.CounterpartySnapshotID,
				CounterpartyResponseAppealID: req.CounterpartyResponseAppealID,
				CounterpartyReference:        req.CounterpartyReference,
				Reason:                       req.Reason,
				Divergences:                  append([]string(nil), req.Divergences...),
				Metadata:                     req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge-counterparty-ruling") && strings.Contains(r.URL.Path, "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals/"):
			cellID, snapshotID, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealPath(r.URL.Path, "/acknowledge-counterparty-ruling")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledge(r, cellID, snapshotID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealRuling(r.Context(), cellID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledgeRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				SnapshotID:            req.SnapshotID,
				CounterpartyReference: req.CounterpartyReference,
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/dispute-counterparty-ruling") && strings.Contains(r.URL.Path, "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals/"):
			cellID, snapshotID, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealPath(r.URL.Path, "/dispute-counterparty-ruling")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal dispute request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDispute(r, cellID, snapshotID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DisputeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealRuling(r.Context(), cellID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				SnapshotID:            req.SnapshotID,
				CounterpartyReference: req.CounterpartyReference,
				Reason:                req.Reason,
				Divergences:           append([]string(nil), req.Divergences...),
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/escalate-counterparty-dispute") && strings.Contains(r.URL.Path, "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals/"):
			cellID, snapshotID, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealPath(r.URL.Path, "/escalate-counterparty-dispute")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeEscalationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal dispute escalation request: "+err.Error())
				return
			}
			if strings.TrimSpace(req.SnapshotID) == "" {
				req.SnapshotID = snapshotID
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealEscalate(r, cellID, snapshotID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.EscalateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDispute(r.Context(), cellID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeEscalationRequest{
				ActorDID:                            safeSecureCellActorDID(authCtx),
				SnapshotID:                          req.SnapshotID,
				CounterpartyReference:               req.CounterpartyReference,
				AppealingParty:                      req.AppealingParty,
				CorrectionBoardParty:                req.CorrectionBoardParty,
				EnforcementAcknowledgementParty:     req.EnforcementAcknowledgementParty,
				Summary:                             req.Summary,
				Description:                         req.Description,
				EvidenceIDs:                         append([]string(nil), req.EvidenceIDs...),
				Divergences:                         append([]string(nil), req.Divergences...),
				CorrectionBoardReviewThreshold:      req.CorrectionBoardReviewThreshold,
				EligibleCorrectionBoardReviewerDIDs: append([]string(nil), req.EligibleCorrectionBoardReviewerDIDs...),
				Reason:                              req.Reason,
				Metadata:                            req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge-counterparty-ruling") && strings.Contains(r.URL.Path, "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals/"):
			cellID, snapshotID, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealPath(r.URL.Path, "/acknowledge-counterparty-ruling")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealAcknowledge(r, cellID, snapshotID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealRuling(r.Context(), cellID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealAcknowledgeRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				SnapshotID:            req.SnapshotID,
				CounterpartyReference: req.CounterpartyReference,
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/dispute-counterparty-ruling") && strings.Contains(r.URL.Path, "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals/"):
			cellID, snapshotID, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealPath(r.URL.Path, "/dispute-counterparty-ruling")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealDisputeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal dispute request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealDispute(r, cellID, snapshotID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DisputeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealRuling(r.Context(), cellID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealDisputeRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				SnapshotID:            req.SnapshotID,
				CounterpartyReference: req.CounterpartyReference,
				Reason:                req.Reason,
				Divergences:           append([]string(nil), req.Divergences...),
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/escalate-counterparty-dispute") && strings.Contains(r.URL.Path, "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals/"):
			cellID, snapshotID, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealPath(r.URL.Path, "/escalate-counterparty-dispute")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealDisputeEscalationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal dispute escalation request: "+err.Error())
				return
			}
			if strings.TrimSpace(req.SnapshotID) == "" {
				req.SnapshotID = snapshotID
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealEscalate(r, cellID, snapshotID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.EscalateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealDispute(r.Context(), cellID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealDisputeEscalationRequest{
				ActorDID:                            safeSecureCellActorDID(authCtx),
				SnapshotID:                          req.SnapshotID,
				CounterpartyReference:               req.CounterpartyReference,
				AppealingParty:                      req.AppealingParty,
				CorrectionBoardParty:                req.CorrectionBoardParty,
				EnforcementAcknowledgementParty:     req.EnforcementAcknowledgementParty,
				Summary:                             req.Summary,
				Description:                         req.Description,
				EvidenceIDs:                         append([]string(nil), req.EvidenceIDs...),
				Divergences:                         append([]string(nil), req.Divergences...),
				CorrectionBoardReviewThreshold:      req.CorrectionBoardReviewThreshold,
				EligibleCorrectionBoardReviewerDIDs: append([]string(nil), req.EligibleCorrectionBoardReviewerDIDs...),
				Reason:                              req.Reason,
				Metadata:                            req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge-counterparty-ruling") && strings.Contains(r.URL.Path, "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundles/"):
			cellID, snapshotID, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundlePath(r.URL.Path, "/acknowledge-counterparty-ruling")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal review bundle acknowledge request: "+err.Error())
				return
			}
			if strings.TrimSpace(req.SnapshotID) == "" {
				req.SnapshotID = snapshotID
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleAcknowledge(r, cellID, snapshotID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleRuling(r.Context(), cellID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleAcknowledgeRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				SnapshotID:            req.SnapshotID,
				CounterpartyReference: req.CounterpartyReference,
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/dispute-counterparty-ruling") && strings.Contains(r.URL.Path, "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundles/"):
			cellID, snapshotID, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundlePath(r.URL.Path, "/dispute-counterparty-ruling")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDisputeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal review bundle dispute request: "+err.Error())
				return
			}
			if strings.TrimSpace(req.SnapshotID) == "" {
				req.SnapshotID = snapshotID
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDispute(r, cellID, snapshotID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DisputeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleRuling(r.Context(), cellID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDisputeRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				SnapshotID:            req.SnapshotID,
				CounterpartyReference: req.CounterpartyReference,
				Reason:                req.Reason,
				Divergences:           append([]string(nil), req.Divergences...),
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/escalate-counterparty-dispute") && strings.Contains(r.URL.Path, "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundles/"):
			cellID, snapshotID, err := parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundlePath(r.URL.Path, "/escalate-counterparty-dispute")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDisputeEscalationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal review bundle dispute escalation request: "+err.Error())
				return
			}
			if strings.TrimSpace(req.SnapshotID) == "" {
				req.SnapshotID = snapshotID
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleEscalate(r, cellID, snapshotID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.EscalateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDispute(r.Context(), cellID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleDisputeEscalationRequest{
				ActorDID:                            safeSecureCellActorDID(authCtx),
				SnapshotID:                          req.SnapshotID,
				CounterpartyReference:               req.CounterpartyReference,
				AppealingParty:                      req.AppealingParty,
				CorrectionBoardParty:                req.CorrectionBoardParty,
				EnforcementAcknowledgementParty:     req.EnforcementAcknowledgementParty,
				Summary:                             req.Summary,
				Description:                         req.Description,
				EvidenceIDs:                         append([]string(nil), req.EvidenceIDs...),
				Divergences:                         append([]string(nil), req.Divergences...),
				CorrectionBoardReviewThreshold:      req.CorrectionBoardReviewThreshold,
				EligibleCorrectionBoardReviewerDIDs: append([]string(nil), req.EligibleCorrectionBoardReviewerDIDs...),
				Reason:                              req.Reason,
				Metadata:                            req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/escalate-counterparty-dispute") && strings.Contains(r.URL.Path, "/alignment-response-appeals/") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, responseAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionPath(r.URL.Path, "/escalate-counterparty-dispute")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDisputeEscalationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty dispute escalation request: "+err.Error())
				return
			}
			authReq := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehearingRequest{
				ActorIdentity:                       req.ActorIdentity,
				PolicyReceipt:                       req.PolicyReceipt,
				AppealingParty:                      req.AppealingParty,
				CorrectionBoardParty:                req.CorrectionBoardParty,
				EnforcementAcknowledgementParty:     req.EnforcementAcknowledgementParty,
				Summary:                             req.Summary,
				Description:                         req.Description,
				EvidenceIDs:                         append([]string(nil), req.EvidenceIDs...),
				CorrectionBoardReviewThreshold:      req.CorrectionBoardReviewThreshold,
				EligibleCorrectionBoardReviewerDIDs: append([]string(nil), req.EligibleCorrectionBoardReviewerDIDs...),
				Reason:                              req.Reason,
				Metadata:                            req.Metadata,
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehear(r, cellID, challengeAppealID, responseAppealID, &authReq)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.EscalateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDispute(r.Context(), cellID, responseAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDisputeEscalationRequest{
				ActorDID:                            safeSecureCellActorDID(authCtx),
				CounterpartySnapshotID:              req.CounterpartySnapshotID,
				CounterpartyResponseAppealID:        req.CounterpartyResponseAppealID,
				CounterpartyReference:               req.CounterpartyReference,
				AppealingParty:                      req.AppealingParty,
				CorrectionBoardParty:                req.CorrectionBoardParty,
				EnforcementAcknowledgementParty:     req.EnforcementAcknowledgementParty,
				Summary:                             req.Summary,
				Description:                         req.Description,
				EvidenceIDs:                         append([]string(nil), req.EvidenceIDs...),
				Divergences:                         append([]string(nil), req.Divergences...),
				CorrectionBoardReviewThreshold:      req.CorrectionBoardReviewThreshold,
				EligibleCorrectionBoardReviewerDIDs: append([]string(nil), req.EligibleCorrectionBoardReviewerDIDs...),
				Reason:                              req.Reason,
				Metadata:                            req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/rule") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/rule")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRulingRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal rule request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRule(r, cellID, challengeAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RuleFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(r.Context(), cellID, challengeAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRulingRequest{
				ActorDID:          safeSecureCellActorDID(authCtx),
				BoardParty:        req.BoardParty,
				Ruling:            req.Ruling,
				RulingSummary:     req.RulingSummary,
				RulingDescription: req.RulingDescription,
				EvidenceIDs:       append([]string(nil), req.EvidenceIDs...),
				Reason:            req.Reason,
				Metadata:          req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/delegate-review") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/delegate-review")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionDelegationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal delegation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealDelegateReview(r, cellID, challengeAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DelegateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealReview(r.Context(), cellID, challengeAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionDelegationRequest{
				ActorDID:  safeSecureCellActorDID(authCtx),
				TargetDID: req.TargetDID,
				Reason:    req.Reason,
				Metadata:  req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/recuse") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/recuse")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuseRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal recuse request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuse(r, cellID, challengeAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RecuseFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealReview(r.Context(), cellID, challengeAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuseRequest{
				ActorDID:    safeSecureCellActorDID(authCtx),
				BoardParty:  req.BoardParty,
				Summary:     req.Summary,
				Description: req.Description,
				EvidenceIDs: append([]string(nil), req.EvidenceIDs...),
				Reason:      req.Reason,
				Metadata:    req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/rehear") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/rehear")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehearingRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal rehearing request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehear(r, cellID, challengeAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RehearFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(r.Context(), cellID, challengeAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehearingRequest{
				ActorDID:                  safeSecureCellActorDID(authCtx),
				AppealingParty:            req.AppealingParty,
				Summary:                   req.Summary,
				Description:               req.Description,
				EvidenceIDs:               append([]string(nil), req.EvidenceIDs...),
				BoardReviewThreshold:      req.BoardReviewThreshold,
				EligibleBoardReviewerDIDs: append([]string(nil), req.EligibleBoardReviewerDIDs...),
				Reason:                    req.Reason,
				Metadata:                  req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge-enforcement") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/acknowledge-enforcement")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledge(r, cellID, challengeAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealEnforcement(r.Context(), cellID, challengeAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgeRequest{
				ActorDID:           safeSecureCellActorDID(authCtx),
				AcknowledgingParty: req.AcknowledgingParty,
				Summary:            req.Summary,
				Description:        req.Description,
				EvidenceIDs:        append([]string(nil), req.EvidenceIDs...),
				Reason:             req.Reason,
				Metadata:           req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge-alignment") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/acknowledge-alignment")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledge(r, cellID, challengeAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignment(r.Context(), cellID, challengeAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledgeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/dispute-alignment") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/dispute-alignment")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDisputeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment dispute request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDispute(r, cellID, challengeAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DisputeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignment(r.Context(), cellID, challengeAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDisputeRequest{
				ActorDID:    safeSecureCellActorDID(authCtx),
				Reason:      req.Reason,
				Divergences: append([]string(nil), req.Divergences...),
				Metadata:    req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge-alignment-automation") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/acknowledge-alignment-automation")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment automation acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAcknowledge(r, cellID, challengeAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomation(r.Context(), cellID, challengeAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAcknowledgeRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				CounterpartyReference: req.CounterpartyReference,
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/dispute-alignment-automation") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/dispute-alignment-automation")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationDisputeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment automation dispute request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationDispute(r, cellID, challengeAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DisputeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomation(r.Context(), cellID, challengeAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationDisputeRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				CounterpartyReference: req.CounterpartyReference,
				Reason:                req.Reason,
				Divergences:           append([]string(nil), req.Divergences...),
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/attest-alignment-correction") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/attest-alignment-correction")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrectionAttestationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment correction attestation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrectionAttest(r, cellID, challengeAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AttestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrection(r.Context(), cellID, challengeAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentCorrectionAttestationRequest{
				ActorDID:               safeSecureCellActorDID(authCtx),
				CounterpartySnapshotID: req.CounterpartySnapshotID,
				CounterpartyReference:  req.CounterpartyReference,
				Reason:                 req.Reason,
				Metadata:               req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/attest-alignment-resolution") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/"):
			cellID, challengeAppealID, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(r.URL.Path, "/attest-alignment-resolution")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolutionAttestationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment resolution attestation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolutionAttest(r, cellID, challengeAppealID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AttestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolution(r.Context(), cellID, challengeAppealID, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResolutionAttestationRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				CounterpartyReference: req.CounterpartyReference,
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge-dispute") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionPath(r.URL.Path, "/acknowledge-dispute")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation counterparty acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledge(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationDispute(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				CounterpartyReference: req.CounterpartyReference,
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/attest-correction") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionPath(r.URL.Path, "/attest-correction")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttestationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation correction attestation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttest(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AttestFederationIncidentDirectiveExtensionAppealReconciliationCorrection(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCorrectionAttestationRequest{
				ActorDID:               safeSecureCellActorDID(authCtx),
				CounterpartySnapshotID: req.CounterpartySnapshotID,
				CounterpartyReference:  req.CounterpartyReference,
				Reason:                 req.Reason,
				Metadata:               req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/attest-resolution") && strings.Contains(r.URL.Path, "/federation/incident-directive-extension-appeal-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionPath(r.URL.Path, "/attest-resolution")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttestationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident directive extension appeal reconciliation resolution attestation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttest(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AttestFederationIncidentDirectiveExtensionAppealReconciliationResolution(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionAttestationRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				CounterpartyReference: req.CounterpartyReference,
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge") && strings.Contains(r.URL.Path, "/federation/incident-report-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentReportReconciliationActionPath(r.URL.Path, "/acknowledge")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportReconciliationAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report reconciliation acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportReconciliationAcknowledge(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentReportReconciliation(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentReportReconciliationAcknowledgeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/dispute") && strings.Contains(r.URL.Path, "/federation/incident-report-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentReportReconciliationActionPath(r.URL.Path, "/dispute")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportReconciliationDisputeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report reconciliation dispute request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportReconciliationDispute(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DisputeFederationIncidentReportReconciliation(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentReportReconciliationDisputeRequest{
				ActorDID:    safeSecureCellActorDID(authCtx),
				Reason:      req.Reason,
				Divergences: append([]string(nil), req.Divergences...),
				Metadata:    req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/resolve") && strings.Contains(r.URL.Path, "/federation/incident-report-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentReportReconciliationActionPath(r.URL.Path, "/resolve")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportReconciliationResolveRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report reconciliation resolve request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportReconciliationResolve(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.ResolveFederationIncidentReportReconciliation(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentReportReconciliationResolveRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge") && strings.Contains(r.URL.Path, "/federation/incident-report-amendment-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentReportAmendmentReconciliationActionPath(r.URL.Path, "/acknowledge")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportAmendmentReconciliationAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report amendment reconciliation acknowledge request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportAmendmentReconciliationAcknowledge(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentReportAmendmentReconciliation(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationAcknowledgeRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/dispute") && strings.Contains(r.URL.Path, "/federation/incident-report-amendment-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentReportAmendmentReconciliationActionPath(r.URL.Path, "/dispute")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportAmendmentReconciliationDisputeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report amendment reconciliation dispute request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportAmendmentReconciliationDispute(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.DisputeFederationIncidentReportAmendmentReconciliation(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationDisputeRequest{
				ActorDID:    safeSecureCellActorDID(authCtx),
				Reason:      req.Reason,
				Divergences: append([]string(nil), req.Divergences...),
				Metadata:    req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/resolve") && strings.Contains(r.URL.Path, "/federation/incident-report-amendment-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentReportAmendmentReconciliationActionPath(r.URL.Path, "/resolve")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportAmendmentReconciliationResolveRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report amendment reconciliation resolve request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportAmendmentReconciliationResolve(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.ResolveFederationIncidentReportAmendmentReconciliation(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationResolveRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/acknowledge-dispute") && strings.Contains(r.URL.Path, "/federation/incident-report-amendment-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentReportAmendmentReconciliationActionPath(r.URL.Path, "/acknowledge-dispute")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportAmendmentReconciliationCounterpartyAcknowledgeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report amendment reconciliation dispute acknowledgement request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAcknowledge(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AcknowledgeFederationIncidentReportAmendmentReconciliationDispute(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAcknowledgeRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				CounterpartyReference: req.CounterpartyReference,
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/attest-correction") && strings.Contains(r.URL.Path, "/federation/incident-report-amendment-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentReportAmendmentReconciliationActionPath(r.URL.Path, "/attest-correction")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportAmendmentReconciliationCorrectionAttestationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report amendment reconciliation correction attestation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportAmendmentReconciliationCorrectionAttest(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AttestFederationIncidentReportAmendmentReconciliationCorrection(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCorrectionAttestationRequest{
				ActorDID:               safeSecureCellActorDID(authCtx),
				CounterpartySnapshotID: req.CounterpartySnapshotID,
				CounterpartyReference:  req.CounterpartyReference,
				Reason:                 req.Reason,
				Metadata:               req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/attest-resolution") && strings.Contains(r.URL.Path, "/federation/incident-report-amendment-reconciliations/"):
			cellID, comparisonKey, err := parseSecureCellFederationIncidentReportAmendmentReconciliationActionPath(r.URL.Path, "/attest-resolution")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationIncidentReportAmendmentReconciliationResolutionAttestationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation incident report amendment reconciliation resolution attestation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationIncidentReportAmendmentReconciliationResolutionAttest(r, cellID, comparisonKey, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AttestFederationIncidentReportAmendmentReconciliationResolution(r.Context(), cellID, comparisonKey, securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationResolutionAttestationRequest{
				ActorDID:              safeSecureCellActorDID(authCtx),
				CounterpartyReference: req.CounterpartyReference,
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/approve") && strings.Contains(r.URL.Path, "/federation/counterproposals/"):
			cellID, counterproposalID, err := parseSecureCellFederationCounterproposalActionPath(r.URL.Path, "/approve")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation counterproposal approve request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationCounterproposalApprove(r, cellID, counterproposalID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.ApproveFederationCounterproposal(r.Context(), cellID, counterproposalID, securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/reject") && strings.Contains(r.URL.Path, "/federation/counterproposals/"):
			cellID, counterproposalID, err := parseSecureCellFederationCounterproposalActionPath(r.URL.Path, "/reject")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation counterproposal reject request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationCounterproposalReject(r, cellID, counterproposalID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RejectFederationCounterproposal(r.Context(), cellID, counterproposalID, securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/renew") && strings.Contains(r.URL.Path, "/federation/contracts/"):
			cellID, contractID, err := parseSecureCellFederationContractActionPath(r.URL.Path, "/renew")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellFederationContractRenewRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation contract renew request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationContractRenew(r, cellID, contractID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RenewFederationContract(r.Context(), cellID, contractID, securecellsintegration.SecureCellFederationContractRenewRequest{
				ActorDID:               safeSecureCellActorDID(authCtx),
				SessionScopeIDs:        append([]string(nil), req.SessionScopeIDs...),
				DataClasses:            append([]string(nil), req.DataClasses...),
				ComputeZones:           append([]string(nil), req.ComputeZones...),
				AllowedActions:         append([]string(nil), req.AllowedActions...),
				OfferedSessionScopeIDs: append([]string(nil), req.OfferedSessionScopeIDs...),
				OfferedDataClasses:     append([]string(nil), req.OfferedDataClasses...),
				OfferedComputeZones:    append([]string(nil), req.OfferedComputeZones...),
				OfferedActions:         append([]string(nil), req.OfferedActions...),
				Resource:               req.Resource,
				Reason:                 req.Reason,
				Metadata:               req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/suspend") && strings.Contains(r.URL.Path, "/federation/contracts/"):
			cellID, contractID, err := parseSecureCellFederationContractActionPath(r.URL.Path, "/suspend")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation contract suspend request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationContractSuspend(r, cellID, contractID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.SuspendFederationContract(r.Context(), cellID, contractID, securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/resume") && strings.Contains(r.URL.Path, "/federation/contracts/"):
			cellID, contractID, err := parseSecureCellFederationContractActionPath(r.URL.Path, "/resume")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation contract resume request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationContractResume(r, cellID, contractID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.ResumeFederationContract(r.Context(), cellID, contractID, securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/revoke") && strings.Contains(r.URL.Path, "/federation/contracts/"):
			cellID, contractID, err := parseSecureCellFederationContractActionPath(r.URL.Path, "/revoke")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell federation contract revoke request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellFederationContractRevoke(r, cellID, contractID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RevokeFederationContract(r.Context(), cellID, contractID, securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/outcome-bundles/fetch") && strings.Contains(r.URL.Path, "/decisions/"):
			cellID, sessionID, threadID, decisionID, err := parseSecureCellSessionThreadDecisionOutcomeBundleFetchPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell thread decision outcome bundle request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionThreadDecisionOutcomeBundleFetch(r, cellID, sessionID, threadID, decisionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			req.Metadata = secureCellDecisionGovernanceMetadata(req.Metadata, req.DeadlineAt, req.PolicyTemplate, req.AutoEscalation)
			req.Metadata = secureCellOutcomeBundleMetadata(req.Metadata, decisionID, req.OutcomeBundleID, req.OutcomeBundleName, req.OutcomeBundleType, req.Comment)
			result, err := app.secureCellService.GetCell(r.Context(), cellID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case (strings.HasSuffix(r.URL.Path, "/vote") || strings.HasSuffix(r.URL.Path, "/approve") || strings.HasSuffix(r.URL.Path, "/comments") || strings.HasSuffix(r.URL.Path, "/contain-outputs") || strings.HasSuffix(r.URL.Path, "/release-outputs") || strings.HasSuffix(r.URL.Path, "/delegate") || strings.HasSuffix(r.URL.Path, "/escalate") || strings.HasSuffix(r.URL.Path, "/outcome-bundles") || strings.HasSuffix(r.URL.Path, "/resume") || strings.HasSuffix(r.URL.Path, "/quarantine") || strings.HasSuffix(r.URL.Path, "/close")) && strings.Contains(r.URL.Path, "/decisions/"):
			cellID, sessionID, threadID, decisionID, action, err := parseSecureCellSessionThreadDecisionLifecycleActionPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell thread decision lifecycle request: "+err.Error())
				return
			}
			var authCtx *secureCellAuthContext
			switch action {
			case "vote":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionVote(r, cellID, sessionID, threadID, decisionID, &req)
			case "approve":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionApprove(r, cellID, sessionID, threadID, decisionID, &req)
			case "comments":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionComment(r, cellID, sessionID, threadID, decisionID, &req)
			case "contain-outputs":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionContainOutputs(r, cellID, sessionID, threadID, decisionID, &req)
			case "release-outputs":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionReleaseOutputs(r, cellID, sessionID, threadID, decisionID, &req)
			case "delegate":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionDelegate(r, cellID, sessionID, threadID, decisionID, &req)
			case "escalate":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionEscalate(r, cellID, sessionID, threadID, decisionID, &req)
			case "outcome-bundles":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionOutcomeBundleCreate(r, cellID, sessionID, threadID, decisionID, &req)
			case "fetch":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionOutcomeBundleFetch(r, cellID, sessionID, threadID, decisionID, &req)
			case "resume":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionResume(r, cellID, sessionID, threadID, decisionID, &req)
			case "quarantine":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionQuarantine(r, cellID, sessionID, threadID, decisionID, &req)
			case "close":
				authCtx, err = app.authorizeSecureCellSessionThreadDecisionClose(r, cellID, sessionID, threadID, decisionID, &req)
			default:
				err = fmt.Errorf("unsupported secure cell thread decision lifecycle action")
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			req.Metadata = secureCellDecisionGovernanceMetadata(req.Metadata, req.DeadlineAt, req.PolicyTemplate, req.AutoEscalation)
			req.Metadata = secureCellDecisionMutationMetadata(req.Metadata, decisionID, req.Comment, req.RelatedOutputIDs, req.ApprovalThreshold, firstNonEmpty(strings.TrimSpace(req.VoteChoice), strings.TrimSpace(req.ApprovalVote)))
			lifecycle := securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			}
			var result *securecellsintegration.SecureCellResult
			switch action {
			case "vote":
				if req.ApprovalThreshold != nil && *req.ApprovalThreshold <= 0 {
					writeSecureCellAPIError(w, http.StatusBadRequest, "approval_threshold must be greater than zero")
					return
				}
				voteChoice := strings.TrimSpace(firstNonEmpty(req.VoteChoice, req.ApprovalVote))
				if voteChoice == "" {
					voteChoice = "approve"
				}
				if !secureCellDecisionVoteChoiceAllowed(voteChoice) {
					writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell decision vote choice")
					return
				}
				lifecycle.Metadata = secureCellDecisionVoteMetadata(lifecycle.Metadata, req.ApprovalThreshold, voteChoice, req.VoteRole, req.Comment)
				result, err = app.secureCellService.VoteThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle, securecellsintegration.SecureCellThreadDecisionVoteChoice(strings.ToLower(voteChoice)))
			case "approve":
				if req.ApprovalThreshold != nil && *req.ApprovalThreshold <= 0 {
					writeSecureCellAPIError(w, http.StatusBadRequest, "approval_threshold must be greater than zero")
					return
				}
				voteChoice := strings.TrimSpace(firstNonEmpty(req.VoteChoice, req.ApprovalVote))
				if voteChoice == "" {
					voteChoice = "approve"
				}
				if !strings.EqualFold(voteChoice, "approve") {
					writeSecureCellAPIError(w, http.StatusBadRequest, "approve route only accepts approve votes")
					return
				}
				lifecycle.Metadata = secureCellDecisionVoteMetadata(lifecycle.Metadata, req.ApprovalThreshold, voteChoice, req.VoteRole, req.Comment)
				result, err = app.secureCellService.ApproveThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle)
			case "comments":
				if strings.TrimSpace(req.Comment) == "" {
					writeSecureCellAPIError(w, http.StatusBadRequest, "decision comment is required")
					return
				}
				result, err = app.secureCellService.CommentThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, securecellsintegration.SecureCellThreadDecisionCommentRequest{
					ActorDID: safeSecureCellActorDID(authCtx),
					Comment:  req.Comment,
					Reason:   req.Reason,
					Metadata: req.Metadata,
				})
			case "contain-outputs":
				lifecycle.Metadata = secureCellDecisionOutputContainmentMetadata(lifecycle.Metadata, req.RelatedOutputIDs, req.Comment)
				result, err = app.secureCellService.ContainThreadDecisionOutputs(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle)
			case "release-outputs":
				lifecycle.Metadata = secureCellDecisionOutputReleaseMetadata(lifecycle.Metadata, req.RelatedOutputIDs, req.Comment)
				result, err = app.secureCellService.ReleaseThreadDecisionOutputs(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle)
			case "delegate":
				lifecycle.Metadata = secureCellDecisionDelegationMetadata(lifecycle.Metadata, decisionID, req.DelegatedToDID, req.Comment, req.Reason)
				result, err = app.secureCellService.DelegateThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, securecellsintegration.SecureCellThreadDecisionDelegationRequest{
					ActorDID:  safeSecureCellActorDID(authCtx),
					TargetDID: req.DelegatedToDID,
					Reason:    req.Reason,
					Metadata:  lifecycle.Metadata,
				})
			case "escalate":
				lifecycle.Metadata = secureCellDecisionEscalationMetadata(lifecycle.Metadata, decisionID, req.EscalationReason, req.Comment, req.Reason)
				result, err = app.secureCellService.EscalateThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, securecellsintegration.SecureCellThreadDecisionDelegationRequest{
					ActorDID:  safeSecureCellActorDID(authCtx),
					TargetDID: req.DelegatedToDID,
					Reason:    firstNonEmpty(req.EscalationReason, req.Reason),
					Metadata:  lifecycle.Metadata,
				})
			case "outcome-bundles":
				lifecycle.Metadata = secureCellOutcomeBundleMetadata(lifecycle.Metadata, decisionID, req.OutcomeBundleID, req.OutcomeBundleName, req.OutcomeBundleType, req.Comment)
				result, err = app.secureCellService.PublishThreadDecisionOutcome(r.Context(), cellID, sessionID, threadID, decisionID, securecellsintegration.SecureCellThreadDecisionOutcomeRequest{
					ActorDID:         safeSecureCellActorDID(authCtx),
					Title:            req.OutcomeBundleName,
					Summary:          req.Comment,
					Classification:   "",
					OutcomeType:      req.OutcomeBundleType,
					RelatedOutputIDs: req.RelatedOutputIDs,
					Reason:           req.Reason,
					Metadata:         lifecycle.Metadata,
				})
			case "fetch":
				lifecycle.Metadata = secureCellOutcomeBundleMetadata(lifecycle.Metadata, decisionID, req.OutcomeBundleID, req.OutcomeBundleName, req.OutcomeBundleType, req.Comment)
				result, err = app.secureCellService.GetCell(r.Context(), cellID)
			case "resume":
				result, err = app.secureCellService.ResumeThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle)
			case "quarantine":
				result, err = app.secureCellService.QuarantineThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle)
			case "close":
				result, err = app.secureCellService.CloseThreadDecision(r.Context(), cellID, sessionID, threadID, decisionID, lifecycle)
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/decisions") && strings.Contains(r.URL.Path, "/threads/"):
			cellID, sessionID, threadID, err := parseSecureCellSessionThreadActionPath(r.URL.Path, "/decisions")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellThreadDecisionRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell thread decision request: "+err.Error())
				return
			}
			if req.ApprovalThreshold != nil && *req.ApprovalThreshold <= 0 {
				writeSecureCellAPIError(w, http.StatusBadRequest, "approval_threshold must be greater than zero")
				return
			}
			authCtx, err := app.authorizeSecureCellSessionThreadDecisionCreate(r, cellID, sessionID, threadID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			req.Metadata = secureCellDecisionGovernanceMetadata(req.Metadata, req.DeadlineAt, req.PolicyTemplate, req.AutoEscalation)
			result, err := app.secureCellService.CreateThreadDecision(r.Context(), cellID, securecellsintegration.SecureCellThreadDecisionRequest{
				SessionID:             sessionID,
				ThreadID:              threadID,
				ActorDID:              safeSecureCellActorDID(authCtx),
				Title:                 req.Title,
				Summary:               req.Summary,
				Classification:        req.Classification,
				GovernanceTemplate:    secureCellDecisionServiceGovernanceTemplate(req),
				SLATemplate:           secureCellDecisionServiceSLATemplate(req),
				SectorPolicyPack:      secureCellDecisionServiceSectorPolicyPack(req),
				ApprovalThreshold:     safeSecureCellOptionalInt(req.ApprovalThreshold),
				EligibleApproverDIDs:  req.EligibleApproverDIDs,
				RequiredApproverRoles: req.RequiredApproverRoles,
				AllowedVoteChoices:    append([]securecellsintegration.SecureCellThreadDecisionVoteChoice(nil), req.AllowedVoteChoices...),
				RejectorRoles:         append([]string(nil), req.RejectorRoles...),
				AbstainerRoles:        append([]string(nil), req.AbstainerRoles...),
				ReopenRoles:           append([]string(nil), req.ReopenRoles...),
				EscalationLadder:      append([]securecellsintegration.SecureCellDecisionEscalationTier(nil), req.EscalationLadder...),
				AutoEscalateToDID:     strings.TrimSpace(req.AutoEscalateToDID),
				EscalationDueAt:       safeSecureCellOptionalTime(req.EscalationDueAt),
				ResolutionDueAt:       secureCellDecisionResolutionDueAt(req),
				RelatedExchangeIDs:    req.RelatedExchangeIDs,
				RelatedOutputIDs:      req.RelatedOutputIDs,
				Reason:                req.Reason,
				Metadata:              req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/messages") && strings.Contains(r.URL.Path, "/threads/"):
			cellID, sessionID, threadID, err := parseSecureCellSessionThreadActionPath(r.URL.Path, "/messages")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellThreadMessageRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell thread message request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionThreadMessage(r, cellID, sessionID, threadID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.PostThreadMessage(r.Context(), cellID, securecellsintegration.SecureCellThreadMessageRequest{
				SessionID:      sessionID,
				ThreadID:       threadID,
				ActorDID:       safeSecureCellActorDID(authCtx),
				Name:           req.Name,
				ExchangeType:   req.ExchangeType,
				Classification: req.Classification,
				Resource:       req.Resource,
				Summary:        req.Summary,
				Recipients:     req.Recipients,
				IntegrityHash:  req.IntegrityHash,
				Reason:         req.Reason,
				Metadata:       req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case (strings.HasSuffix(r.URL.Path, "/close") || strings.HasSuffix(r.URL.Path, "/resume") || strings.HasSuffix(r.URL.Path, "/quarantine")) && strings.Contains(r.URL.Path, "/threads/"):
			cellID, sessionID, threadID, action, err := parseSecureCellSessionThreadLifecycleActionPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell thread lifecycle request: "+err.Error())
				return
			}
			var authCtx *secureCellAuthContext
			switch action {
			case "close":
				authCtx, err = app.authorizeSecureCellSessionThreadClose(r, cellID, sessionID, threadID, &req)
			case "resume":
				authCtx, err = app.authorizeSecureCellSessionThreadResume(r, cellID, sessionID, threadID, &req)
			case "quarantine":
				authCtx, err = app.authorizeSecureCellSessionThreadQuarantine(r, cellID, sessionID, threadID, &req)
			default:
				err = fmt.Errorf("unsupported secure cell session thread lifecycle action")
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			lifecycle := securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			}
			var result *securecellsintegration.SecureCellResult
			switch action {
			case "close":
				result, err = app.secureCellService.CloseThread(r.Context(), cellID, sessionID, threadID, lifecycle)
			case "resume":
				result, err = app.secureCellService.ResumeThread(r.Context(), cellID, sessionID, threadID, lifecycle)
			case "quarantine":
				result, err = app.secureCellService.QuarantineThread(r.Context(), cellID, sessionID, threadID, lifecycle)
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/threads"):
			cellID, sessionID, err := parseSecureCellSessionActionPath(r.URL.Path, "/threads")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellSessionThreadStartRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session thread start request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionThreadStart(r, cellID, sessionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.StartThread(r.Context(), cellID, securecellsintegration.SecureCellSessionThreadStartRequest{
				SessionID:       sessionID,
				ActorDID:        safeSecureCellActorDID(authCtx),
				Name:            req.Name,
				Purpose:         req.Purpose,
				ParticipantDIDs: req.ParticipantDIDs,
				DataClasses:     req.DataClasses,
				Reason:          req.Reason,
				Metadata:        req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/exchange"):
			cellID, sessionID, err := parseSecureCellSessionActionPath(r.URL.Path, "/exchange")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellSessionExchangeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session exchange request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionExchange(r, cellID, sessionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RecordExchange(r.Context(), cellID, securecellsintegration.SecureCellSessionExchangeRequest{
				ActorDID:       safeSecureCellActorDID(authCtx),
				SessionID:      sessionID,
				Name:           req.Name,
				ExchangeType:   req.ExchangeType,
				Classification: req.Classification,
				Resource:       req.Resource,
				Summary:        req.Summary,
				Recipients:     req.Recipients,
				IntegrityHash:  req.IntegrityHash,
				Reason:         req.Reason,
				Metadata:       req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/members") && strings.Contains(r.URL.Path, "/sessions/"):
			cellID, sessionID, err := parseSecureCellSessionActionPath(r.URL.Path, "/members")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellSessionMemberMutationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session member mutation request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionMemberAdmit(r, cellID, sessionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AddSessionMember(r.Context(), cellID, securecellsintegration.SecureCellSessionMemberTransitionRequest{
				ParticipantDID: req.ParticipantDID,
				ActorDID:       safeSecureCellActorDID(authCtx),
				Reason:         req.Reason,
				Metadata:       req.Metadata,
			}, sessionID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/remove") && strings.Contains(r.URL.Path, "/sessions/"):
			cellID, sessionID, participantDID, err := parseSecureCellSessionMemberActionPath(r.URL.Path, "/remove")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellSessionMemberMutationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session member removal request: "+err.Error())
				return
			}
			if strings.TrimSpace(req.ParticipantDID) == "" {
				req.ParticipantDID = participantDID
			}
			authCtx, err := app.authorizeSecureCellSessionMemberRemove(r, cellID, sessionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.RemoveSessionMember(r.Context(), cellID, securecellsintegration.SecureCellSessionMemberTransitionRequest{
				ParticipantDID: req.ParticipantDID,
				ActorDID:       safeSecureCellActorDID(authCtx),
				Reason:         req.Reason,
				Metadata:       req.Metadata,
			}, sessionID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case (strings.HasSuffix(r.URL.Path, "/pause") || strings.HasSuffix(r.URL.Path, "/resume") || strings.HasSuffix(r.URL.Path, "/quarantine")) && strings.Contains(r.URL.Path, "/sessions/"):
			cellID, sessionID, action, err := parseSecureCellSessionLifecycleActionPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session lifecycle request: "+err.Error())
				return
			}
			var authCtx *secureCellAuthContext
			switch action {
			case "pause":
				authCtx, err = app.authorizeSecureCellSessionPause(r, cellID, sessionID, &req)
			case "resume":
				authCtx, err = app.authorizeSecureCellSessionResume(r, cellID, sessionID, &req)
			case "quarantine":
				authCtx, err = app.authorizeSecureCellSessionQuarantine(r, cellID, sessionID, &req)
			default:
				err = fmt.Errorf("unsupported secure cell session lifecycle action")
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			lifecycle := securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			}
			var result *securecellsintegration.SecureCellResult
			switch action {
			case "pause":
				result, err = app.secureCellService.PauseSession(r.Context(), cellID, sessionID, lifecycle)
			case "resume":
				result, err = app.secureCellService.ResumeSession(r.Context(), cellID, sessionID, lifecycle)
			case "quarantine":
				result, err = app.secureCellService.QuarantineSession(r.Context(), cellID, sessionID, lifecycle)
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/sessions"):
			cellID, err := parseSecureCellID(r.URL.Path, "/sessions")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellSessionStartRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session start request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionStart(r, cellID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.StartSession(r.Context(), cellID, securecellsintegration.SecureCellSessionStartRequest{
				ActorDID:        safeSecureCellActorDID(authCtx),
				Name:            req.Name,
				Purpose:         req.Purpose,
				ParticipantDIDs: req.ParticipantDIDs,
				DataClasses:     req.DataClasses,
				Reason:          req.Reason,
				Metadata:        req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/share"):
			cellID, sessionID, err := parseSecureCellSessionActionPath(r.URL.Path, "/share")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellSessionShareRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session share request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionShare(r, cellID, sessionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.ShareOutput(r.Context(), cellID, securecellsintegration.SecureCellSessionShareRequest{
				ActorDID:       safeSecureCellActorDID(authCtx),
				SessionID:      sessionID,
				Name:           req.Name,
				ArtifactType:   req.ArtifactType,
				Classification: req.Classification,
				Resource:       req.Resource,
				Summary:        req.Summary,
				SharedWith:     req.SharedWith,
				IntegrityHash:  req.IntegrityHash,
				Reason:         req.Reason,
				Metadata:       req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/close"):
			cellID, sessionID, err := parseSecureCellSessionActionPath(r.URL.Path, "/close")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell session close request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellSessionClose(r, cellID, sessionID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.CloseSession(r.Context(), cellID, securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			}, sessionID)
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/members"):
			cellID, err := parseSecureCellID(r.URL.Path, "/members")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellAdmitMemberRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell admission request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellAdmit(r, cellID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.AdmitMember(r.Context(), cellID, securecellsintegration.SecureCellAdmissionRequest{
				Participant: req.Participant,
				ActorDID:    safeSecureCellActorDID(authCtx),
				Reason:      req.Reason,
				Metadata:    req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/members/bulk/quarantine"), strings.HasSuffix(r.URL.Path, "/members/bulk/release"), strings.HasSuffix(r.URL.Path, "/members/bulk/revoke"):
			cellID, action, err := parseSecureCellBulkMemberActionPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellBulkMemberMutationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell bulk mutation request: "+err.Error())
				return
			}
			authProbe := &secureCellMemberMutationRequest{
				ActorIdentity:       req.ActorIdentity,
				PolicyReceipt:       req.PolicyReceipt,
				Reason:              req.Reason,
				QuarantineExpiresAt: req.QuarantineExpiresAt,
				Metadata:            req.Metadata,
			}
			var authCtx *secureCellAuthContext
			switch action {
			case "quarantine":
				authCtx, err = app.authorizeSecureCellQuarantine(r, cellID, authProbe)
			case "release":
				authCtx, err = app.authorizeSecureCellRelease(r, cellID, authProbe)
			case "revoke":
				authCtx, err = app.authorizeSecureCellRevoke(r, cellID, authProbe)
			default:
				err = fmt.Errorf("unsupported secure cell bulk action")
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			bulk := securecellsintegration.SecureCellBulkMemberTransitionRequest{
				ParticipantDIDs:     req.ParticipantDIDs,
				ActorDID:            safeSecureCellActorDID(authCtx),
				Reason:              req.Reason,
				QuarantineExpiresAt: req.QuarantineExpiresAt,
				Metadata:            req.Metadata,
			}
			var result *securecellsintegration.SecureCellBulkMemberTransitionResult
			switch action {
			case "quarantine":
				result, err = app.secureCellService.BulkQuarantineMembers(r.Context(), cellID, bulk)
			case "release":
				result, err = app.secureCellService.BulkReleaseMembers(r.Context(), cellID, bulk)
			case "revoke":
				result, err = app.secureCellService.BulkRevokeMembers(r.Context(), cellID, bulk)
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellBulkMutationResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/quarantine/expire"):
			cellID, err := parseSecureCellID(r.URL.Path, "/quarantine/expire")
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell lifecycle request: "+err.Error())
				return
			}
			authCtx, err := app.authorizeSecureCellExpire(r, cellID, &req)
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			result, err := app.secureCellService.ExpireQuarantinedMembers(r.Context(), cellID, derefSecureCellTime(req.EffectiveAt), securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			})
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/pause"), strings.HasSuffix(r.URL.Path, "/resume"), strings.HasSuffix(r.URL.Path, "/terminate"):
			cellID, action, err := parseSecureCellLifecycleActionPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellLifecycleRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell lifecycle request: "+err.Error())
				return
			}
			var authCtx *secureCellAuthContext
			switch action {
			case "pause":
				authCtx, err = app.authorizeSecureCellPause(r, cellID, &req)
			case "resume":
				authCtx, err = app.authorizeSecureCellResume(r, cellID, &req)
			case "terminate":
				authCtx, err = app.authorizeSecureCellTerminate(r, cellID, &req)
			default:
				err = fmt.Errorf("unsupported secure cell lifecycle action")
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			lifecycle := securecellsintegration.SecureCellLifecycleRequest{
				ActorDID: safeSecureCellActorDID(authCtx),
				Reason:   req.Reason,
				Metadata: req.Metadata,
			}
			var result *securecellsintegration.SecureCellResult
			switch action {
			case "pause":
				result, err = app.secureCellService.PauseCell(r.Context(), cellID, lifecycle)
			case "resume":
				result, err = app.secureCellService.ResumeCell(r.Context(), cellID, lifecycle)
			case "terminate":
				result, err = app.secureCellService.TerminateCell(r.Context(), cellID, lifecycle)
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		case strings.HasSuffix(r.URL.Path, "/quarantine"), strings.HasSuffix(r.URL.Path, "/revoke"), strings.HasSuffix(r.URL.Path, "/release"):
			cellID, participantDID, action, err := parseSecureCellMemberActionPath(r.URL.Path)
			if err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			var req secureCellMemberMutationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeSecureCellAPIError(w, http.StatusBadRequest, "invalid secure cell member mutation request: "+err.Error())
				return
			}
			if strings.TrimSpace(req.ParticipantDID) == "" {
				req.ParticipantDID = participantDID
			}
			var authCtx *secureCellAuthContext
			switch action {
			case "release":
				authCtx, err = app.authorizeSecureCellRelease(r, cellID, &req)
			case "quarantine":
				authCtx, err = app.authorizeSecureCellQuarantine(r, cellID, &req)
			case "revoke":
				authCtx, err = app.authorizeSecureCellRevoke(r, cellID, &req)
			default:
				err = fmt.Errorf("unsupported secure cell member action")
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellAuthorizationStatus(err, http.StatusForbidden), err.Error())
				return
			}
			req.Metadata = secureCellRequestMetadataWithAuthContext(req.Metadata, authCtx)
			mutation := securecellsintegration.SecureCellMemberTransitionRequest{
				ParticipantDID:      req.ParticipantDID,
				ActorDID:            safeSecureCellActorDID(authCtx),
				Reason:              req.Reason,
				QuarantineExpiresAt: req.QuarantineExpiresAt,
				Metadata:            req.Metadata,
			}
			var result *securecellsintegration.SecureCellResult
			switch action {
			case "release":
				result, err = app.secureCellService.ReleaseMember(r.Context(), cellID, mutation)
			case "quarantine":
				result, err = app.secureCellService.QuarantineMember(r.Context(), cellID, mutation)
			case "revoke":
				result, err = app.secureCellService.RevokeMember(r.Context(), cellID, mutation)
			}
			if err != nil {
				writeSecureCellAPIError(w, secureCellErrorStatus(err, http.StatusInternalServerError), err.Error())
				return
			}
			writeSecureCellJSON(w, http.StatusOK, secureCellResponse{Result: result})
			return
		default:
			writeSecureCellAPIError(w, http.StatusBadRequest, "unsupported secure cell mutation path")
			return
		}
	})
}

func secureCellArtifactsProjection(result *securecellsintegration.SecureCellResult) secureCellArtifactsResponse {
	projection := secureCellArtifactsResponse{}
	if result == nil {
		return projection
	}
	projection.CellID = result.CellID
	projection.Status = result.Status
	projection.Participants = append([]securecellsintegration.SecureCellParticipantState(nil), result.Participants...)
	projection.FederationOrganizations = append([]securecellsintegration.SecureCellFederationOrganization(nil), result.FederationOrganizations...)
	projection.FederationInvitations = append([]securecellsintegration.SecureCellFederationInvitation(nil), result.FederationInvitations...)
	projection.FederationCounterproposals = append([]securecellsintegration.SecureCellFederationCounterproposal(nil), result.FederationCounterproposals...)
	projection.FederationContracts = append([]securecellsintegration.SecureCellFederationContract(nil), result.FederationContracts...)
	projection.FederationCounterpartyAssurance = append([]securecellsintegration.SecureCellFederationCounterpartyAssuranceSnapshot(nil), result.FederationCounterpartyAssurance...)
	projection.FederationIncidents = append([]securecellsintegration.SecureCellFederationIncident(nil), result.FederationIncidents...)
	projection.FederationCounterpartyIncidents = append([]securecellsintegration.SecureCellFederationCounterpartyIncidentSnapshot(nil), result.FederationCounterpartyIncidents...)
	projection.FederationCounterpartyIncidentReports = append([]securecellsintegration.SecureCellFederationCounterpartyIncidentReportSnapshot(nil), result.FederationCounterpartyIncidentReports...)
	projection.FederationCounterpartyIncidentReportAmendments = append([]securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot(nil), result.FederationCounterpartyIncidentReportAmendments...)
	projection.FederationIncidentResponses = append([]securecellsintegration.SecureCellFederationIncidentResponse(nil), result.FederationIncidentResponses...)
	projection.Sessions = append([]securecellsintegration.SecureCellSession(nil), result.Sessions...)
	projection.Threads = append([]securecellsintegration.SecureCellSessionThread(nil), result.Threads...)
	projection.Decisions = append([]securecellsintegration.SecureCellThreadDecision(nil), result.Decisions...)
	projection.DecisionOutcomes = append([]securecellsintegration.SecureCellThreadDecisionOutcome(nil), result.DecisionOutcomes...)
	projection.SharedOutputs = append([]securecellsintegration.SecureCellSharedOutput(nil), result.SharedOutputs...)
	projection.SessionExchanges = append([]securecellsintegration.SecureCellSessionExchange(nil), result.SessionExchanges...)
	projection.Transitions = append([]securecellsintegration.SecureCellTransition(nil), result.Transitions...)
	projection.CreationReceipt = result.CreationReceipt
	projection.ActivationReceipt = result.ActivationReceipt
	projection.ConfidentialExecution = result.ConfidentialExecution
	projection.ExecutionAttestations = append([]evidence.Attestation(nil), result.ExecutionAttestations...)
	projection.ExecutionSeal = result.ExecutionSeal
	if result.ControlLedger != nil && result.ControlLedger.Bundle != nil {
		projection.ControlLedgerID = result.ControlLedger.Bundle.ID
		projection.ControlLedgerContentHash = result.ControlLedger.Bundle.ContentHash
		summary := result.ControlLedger.Summary
		projection.ControlSummary = &summary
	}
	if result.PortablePackage != nil {
		projection.PortablePackageHash = result.PortablePackage.PackageHash
		projection.PortablePackageSigned = result.PortablePackage.Signature != nil
		projection.PortablePackageAnchored = result.PortablePackage.AuditAnchor != nil
	}
	return projection
}

func secureCellFederationProjection(result *securecellsintegration.SecureCellResult) secureCellFederationResponse {
	if result == nil {
		return secureCellFederationResponse{}
	}
	packageHash := ""
	packageSigned := false
	packageAnchored := false
	if result.PortablePackage != nil {
		packageHash = result.PortablePackage.PackageHash
		packageSigned = result.PortablePackage.Signature != nil
		packageAnchored = result.PortablePackage.AuditAnchor != nil
	}
	return secureCellFederationResponse{
		CellID:                               result.CellID,
		Organizations:                        append([]securecellsintegration.SecureCellFederationOrganization(nil), result.FederationOrganizations...),
		Invitations:                          append([]securecellsintegration.SecureCellFederationInvitation(nil), result.FederationInvitations...),
		Counterproposals:                     append([]securecellsintegration.SecureCellFederationCounterproposal(nil), result.FederationCounterproposals...),
		Contracts:                            append([]securecellsintegration.SecureCellFederationContract(nil), result.FederationContracts...),
		CounterpartyAssurance:                append([]securecellsintegration.SecureCellFederationCounterpartyAssuranceSnapshot(nil), result.FederationCounterpartyAssurance...),
		Incidents:                            append([]securecellsintegration.SecureCellFederationIncident(nil), result.FederationIncidents...),
		CounterpartyIncidents:                append([]securecellsintegration.SecureCellFederationCounterpartyIncidentSnapshot(nil), result.FederationCounterpartyIncidents...),
		CounterpartyIncidentReports:          append([]securecellsintegration.SecureCellFederationCounterpartyIncidentReportSnapshot(nil), result.FederationCounterpartyIncidentReports...),
		CounterpartyIncidentReportAmendments: append([]securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentSnapshot(nil), result.FederationCounterpartyIncidentReportAmendments...),
		IncidentResponses:                    append([]securecellsintegration.SecureCellFederationIncidentResponse(nil), result.FederationIncidentResponses...),
		PortablePackageHash:                  packageHash,
		PortablePackageSigned:                packageSigned,
		PortablePackageAnchored:              packageAnchored,
	}
}

func secureCellFederationTrustPackOptions(cellID string, organizationID string) securecellsintegration.SecureCellFederationOrganizationTrustPackOptions {
	cellID = strings.TrimSpace(cellID)
	organizationID = strings.TrimSpace(organizationID)
	return securecellsintegration.SecureCellFederationOrganizationTrustPackOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "federation-overview",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation",
				Description: "Inspect the live federation view for this secure cell.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-organizations",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/organizations?cell_id=" + cellID,
				Description: "List federated organizations across secure cells or narrow to this cell.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-organizations-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/organizations/export?cell_id=" + cellID + "&format=csv",
				Description: "Export federated organization operator views for this secure cell.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-invitations",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/invitations?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List federation invitations for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-invitations-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/invitations/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export federation invitations for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-counterproposals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterproposals?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List replayable federation counterproposals for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-counterproposals-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterproposals/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export federation counterproposal history for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-counterproposals-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterproposals/overdue?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List overdue federation counterproposal milestones for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-counterproposals-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterproposals/overdue/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export overdue federation counterproposal milestones for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "organization-trust-pack",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/trust-pack",
				Description: "Fetch the buyer-ready federation trust pack for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "organization-trust-pack-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/trust-pack/export?format=csv",
				Description: "Export the federation trust pack for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-contracts",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/contracts?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List active and historical federation contracts for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-contracts-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/contracts/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export federation contracts for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-automation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/automation-actions?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List automated federation governance actions for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-automation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/automation-actions/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export automated federation governance actions for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-assurance-findings",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/assurance/findings?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List live federation assurance findings for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-assurance-findings-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/assurance/findings/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export live federation assurance findings for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-assurance-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/assurance/actions?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List automated federation assurance containment actions for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-assurance-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/assurance/actions/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export automated federation assurance containment actions for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "counterparty-assurance",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-assurance?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List imported counterparty assurance bundles for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "counterparty-assurance-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-assurance/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export imported counterparty assurance bundles for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incidents",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incidents?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List local federation incidents declared for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incidents-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incidents/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export local federation incidents declared for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-actions?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List incident-linked lifecycle and automated containment actions for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-actions/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export incident-linked lifecycle and automated containment actions for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-responses",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-responses?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List bilateral federation incident response cases for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-responses-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-responses/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export bilateral federation incident response cases for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-responses-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-responses/overdue?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List overdue bilateral federation incident responses for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-responses-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-responses/overdue/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export overdue bilateral federation incident responses for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-response-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-response-actions?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List bilateral federation incident response actions for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-response-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-response-actions/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export bilateral federation incident response actions for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-directives",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directives?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List bilateral incident directives and work orders for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-directives-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directives/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export bilateral incident directives and work orders for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-directives-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directives/overdue?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List overdue bilateral incident directives and work orders for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-directives-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directives/overdue/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export overdue bilateral incident directives and work orders for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-directive-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-actions?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List directive acknowledgements, completions, and verifications for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-directive-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-actions/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export directive acknowledgements, completions, and verifications for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-directive-extensions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extensions?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List governed directive deadline exception requests for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-directive-extensions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extensions/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export governed directive deadline exception requests for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-directive-extensions-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extensions/overdue?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List overdue directive exception reviews or disputes for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-directive-extensions-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extensions/overdue/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export overdue directive exception reviews or disputes for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-directive-extension-disputes",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-disputes?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List directive extension disputes for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-directive-extension-disputes-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-disputes/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export directive extension disputes for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-directive-extension-automation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-automation-actions?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List automated directive extension escalation or containment actions for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-directive-extension-automation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-automation-actions/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export automated directive extension escalation or containment actions for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-remediations",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-remediations?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List federation incident remediation attestations for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-remediations-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-remediations/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export federation incident remediation attestations for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-verifications",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-verifications?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List opposite-party remediation verification records for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-verifications-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-verifications/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export opposite-party remediation verification records for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-closures",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-closures?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List opposite-party closure attestation records for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-closures-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-closures/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export opposite-party closure attestation records for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-disputes",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-disputes?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List bilateral incident disputes and reopen events for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-disputes-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-disputes/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export bilateral incident disputes and reopen events for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-reports",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-reports?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List governed cross-org incident reporting obligations for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-reports-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-reports/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export governed cross-org incident reporting obligations for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-reports-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-reports/overdue?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List overdue cross-org incident reporting obligations for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-reports-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-reports/overdue/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export overdue cross-org incident reporting obligations for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "counterparty-incident-reports",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-incident-reports?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List imported signed counterparty incident report bundles for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "counterparty-incident-reports-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-incident-reports/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export imported signed counterparty incident report bundles for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "counterparty-incident-report-amendments",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-incident-report-amendments?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List imported signed counterparty incident report amendment bundles for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "counterparty-incident-report-amendments-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-incident-report-amendments/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export imported signed counterparty incident report amendment bundles for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-report-reconciliations",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-reconciliations?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List local-vs-counterparty incident report reconciliations for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-reconciliations-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-reconciliations/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export local-vs-counterparty incident report reconciliations for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-report-amendment-reconciliations",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliations?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List local-vs-counterparty incident report amendment reconciliations for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-amendment-reconciliations-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliations/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export local-vs-counterparty incident report amendment reconciliations for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-report-amendment-reconciliation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliation-actions?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List governed review actions over bilateral incident report amendment reconciliations for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-amendment-reconciliation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliation-actions/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export governed review actions over bilateral incident report amendment reconciliations for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "counterparty-incidents",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-incidents?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List imported counterparty incident bulletins for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "counterparty-incidents-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-incidents/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export imported counterparty incident bulletins for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "organization-incident-bulletin",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/incident-bulletin",
				Description: "Fetch the signed portable federation incident bulletin for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "organization-incident-bulletin-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/incident-bulletin/export?format=csv",
				Description: "Export the signed portable federation incident bulletin for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "organization-incident-report-intake",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/incident-report-bundles/intake",
				Description: "Ingest one signed counterparty incident report bundle for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "organization-incident-report-amendment-intake",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/incident-report-amendment-bundles/intake",
				Description: "Ingest one signed counterparty incident report amendment bundle for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "organization-incident-publish",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/incidents",
				Description: "Publish one evidence-bearing federation incident for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-detail",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/{response_id}",
				Description: "Fetch one bilateral federation incident response case.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/{response_id}/bundle",
				Description: "Fetch the signed portable bilateral incident response bundle.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/{response_id}/bundle/export?format=csv",
				Description: "Export the signed portable bilateral incident response bundle.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-response-acknowledge",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/{response_id}/acknowledge",
				Description: "Acknowledge one bilateral federation incident response case.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-escalate",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/{response_id}/escalate",
				Description: "Escalate one bilateral federation incident response case.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-remediate",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/{response_id}/remediations",
				Description: "Submit one federation incident remediation attestation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-verify-remediation",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/{response_id}/verify-remediation",
				Description: "Verify or reject one federation incident remediation attestation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-attest-closure",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/{response_id}/attest-closure",
				Description: "Submit one opposite-party closure attestation for a bilateral incident response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-dispute",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/{response_id}/dispute",
				Description: "Dispute one bilateral incident response outcome and reopen the coordinated workflow.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-plan",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/{response_id}/directives",
				Description: "Issue one bilateral incident directive or work order for a coordinated incident response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-detail",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directives/{directive_id}",
				Description: "Fetch one bilateral incident directive or work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directives/{directive_id}/bundle",
				Description: "Fetch the signed portable bilateral incident directive bundle.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directives/{directive_id}/bundle/export?format=csv",
				Description: "Export the signed portable bilateral incident directive bundle.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-acknowledge",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directives/{directive_id}/acknowledge",
				Description: "Acknowledge one bilateral incident directive or work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-complete",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directives/{directive_id}/complete",
				Description: "Complete one bilateral incident directive or work order with evidence-bearing closure details.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-verify",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directives/{directive_id}/verify",
				Description: "Accept or reject completion of one bilateral incident directive or work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-plan",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/{response_id}/reports",
				Description: "Plan one governed cross-org incident reporting obligation for a bilateral incident response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-reports/{report_id}/bundle",
				Description: "Fetch the signed portable cross-org incident report bundle.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-reports/{report_id}/bundle/export?format=csv",
				Description: "Export the signed portable cross-org incident report bundle.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-report-submit",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-reports/{report_id}/submit",
				Description: "Submit one governed cross-org incident report.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-acknowledge",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-reports/{report_id}/acknowledge",
				Description: "Acknowledge one governed cross-org incident report.",
				Formats:     []string{"json"},
			},
			{
				ID:          "organization-incident-bulletin-intake",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/incident-bulletin/intake",
				Description: "Ingest one signed counterparty federation incident bulletin for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "organization-assurance-report",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/assurance",
				Description: "Fetch the continuous federation assurance report for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "organization-assurance-report-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/assurance/export?format=csv",
				Description: "Export the continuous federation assurance report for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "organization-assurance-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/assurance/bundle",
				Description: "Fetch the signed reciprocal assurance bundle for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "organization-assurance-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/assurance/bundle/export?format=csv",
				Description: "Export the signed reciprocal assurance bundle for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "organization-assurance-intake",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/assurance/intake",
				Description: "Ingest a signed counterparty assurance bundle for this organization.",
				Formats:     []string{"json"},
			},
		},
	}
}

func secureCellFederationContractBundleOptions(cellID string, contractID string) securecellsintegration.SecureCellFederationContractBundleOptions {
	cellID = strings.TrimSpace(cellID)
	contractID = strings.TrimSpace(contractID)
	return securecellsintegration.SecureCellFederationContractBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "federation-overview",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation",
				Description: "Inspect the live federation view for this secure cell.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-contracts",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/contracts?cell_id=" + cellID,
				Description: "List federation contracts across this secure cell.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-contracts-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/contracts/export?cell_id=" + cellID + "&format=csv",
				Description: "Export federation contracts across this secure cell.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-counterproposals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterproposals?cell_id=" + cellID,
				Description: "List replayable federation counterproposals across this secure cell.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-counterproposals-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterproposals/export?cell_id=" + cellID + "&format=csv",
				Description: "Export federation counterproposal history across this secure cell.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-counterproposals-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterproposals/overdue?cell_id=" + cellID,
				Description: "List overdue federation counterproposal milestones across this secure cell.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-counterproposals-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterproposals/overdue/export?cell_id=" + cellID + "&format=csv",
				Description: "Export overdue federation counterproposal milestones across this secure cell.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-automation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/automation-actions?cell_id=" + cellID + "&contract_id=" + contractID,
				Description: "List automated federation governance actions that touched this contract or its negotiation lineage.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-automation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/automation-actions/export?cell_id=" + cellID + "&contract_id=" + contractID + "&format=csv",
				Description: "Export automated federation governance actions that touched this contract or its negotiation lineage.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-assurance-findings",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/assurance/findings?cell_id=" + cellID + "&contract_id=" + contractID,
				Description: "List live federation assurance findings tied to this contract.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-assurance-findings-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/assurance/findings/export?cell_id=" + cellID + "&contract_id=" + contractID + "&format=csv",
				Description: "Export live federation assurance findings tied to this contract.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-assurance-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/assurance/actions?cell_id=" + cellID + "&contract_id=" + contractID,
				Description: "List automated federation assurance containment actions for this contract.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-assurance-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/assurance/actions/export?cell_id=" + cellID + "&contract_id=" + contractID + "&format=csv",
				Description: "Export automated federation assurance containment actions for this contract.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "contract-detail",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/contracts/" + contractID,
				Description: "Fetch the portable contract bundle for this federated collaboration contract.",
				Formats:     []string{"json"},
			},
			{
				ID:          "contract-detail-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/contracts/" + contractID + "/export?format=csv",
				Description: "Export the portable contract bundle for this federated collaboration contract.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "contract-renew",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/contracts/" + contractID + "/renew",
				Description: "Renew this federation contract with new negotiated terms and replayable policy diffs.",
				Formats:     []string{"json"},
			},
			{
				ID:          "contract-suspend",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/contracts/" + contractID + "/suspend",
				Description: "Suspend this federation contract without destroying the negotiated collaboration trace.",
				Formats:     []string{"json"},
			},
			{
				ID:          "contract-resume",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/contracts/" + contractID + "/resume",
				Description: "Resume this suspended federation contract back to active exchange posture.",
				Formats:     []string{"json"},
			},
			{
				ID:          "contract-revoke",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/contracts/" + contractID + "/revoke",
				Description: "Revoke this federation contract while preserving the historical collaboration trace.",
				Formats:     []string{"json"},
			},
		},
	}
}

func secureCellFederationAssuranceReportOptions(cellID string, organizationID string) securecellsintegration.SecureCellFederationAssuranceReportOptions {
	cellID = strings.TrimSpace(cellID)
	organizationID = strings.TrimSpace(organizationID)
	return securecellsintegration.SecureCellFederationAssuranceReportOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "federation-assurance-findings",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/assurance/findings?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List live federation assurance findings for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-assurance-findings-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/assurance/findings/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export live federation assurance findings for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-assurance-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/assurance/actions?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List automated federation assurance containment actions for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-assurance-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/assurance/actions/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export automated federation assurance containment actions for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "counterparty-assurance",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-assurance?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List imported counterparty assurance bundles for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "counterparty-assurance-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-assurance/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export imported counterparty assurance bundles for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "organization-assurance-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/assurance/bundle",
				Description: "Fetch the signed reciprocal assurance bundle for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "organization-assurance-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/assurance/bundle/export?format=csv",
				Description: "Export the signed reciprocal assurance bundle for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "organization-assurance-intake",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/assurance/intake",
				Description: "Ingest a signed counterparty assurance bundle for this organization.",
				Formats:     []string{"json"},
			},
		},
	}
}

func secureCellFederationAssuranceBundleOptions(cellID string, organizationID string) securecellsintegration.SecureCellFederationAssuranceBundleOptions {
	cellID = strings.TrimSpace(cellID)
	organizationID = strings.TrimSpace(organizationID)
	return securecellsintegration.SecureCellFederationAssuranceBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "organization-assurance-report",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/assurance",
				Description: "Fetch the continuous federation assurance report for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "organization-assurance-report-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/assurance/export?format=csv",
				Description: "Export the continuous federation assurance report for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "counterparty-assurance",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-assurance?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List imported counterparty assurance bundles for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "counterparty-assurance-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-assurance/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export imported counterparty assurance bundles for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "assurance-intake",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/assurance/intake",
				Description: "Ingest a signed counterparty assurance bundle for this organization.",
				Formats:     []string{"json"},
			},
		},
	}
}

func secureCellFederationIncidentBulletinOptions(cellID string, organizationID string) securecellsintegration.SecureCellFederationIncidentBulletinOptions {
	cellID = strings.TrimSpace(cellID)
	organizationID = strings.TrimSpace(organizationID)
	return securecellsintegration.SecureCellFederationIncidentBulletinOptions{
		ExpiresAfter: 24 * time.Hour,
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "federation-incidents",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incidents?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List local federation incidents declared for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incidents-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incidents/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export local federation incidents declared for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "federation-incident-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-actions?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List incident-linked lifecycle and automated containment actions for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "federation-incident-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-actions/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export incident-linked lifecycle and automated containment actions for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "counterparty-incidents",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-incidents?cell_id=" + cellID + "&organization_id=" + organizationID,
				Description: "List imported counterparty incident bulletins for this organization.",
				Formats:     []string{"json"},
			},
			{
				ID:          "counterparty-incidents-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-incidents/export?cell_id=" + cellID + "&organization_id=" + organizationID + "&format=csv",
				Description: "Export imported counterparty incident bulletins for this organization.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-bulletin-intake",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/organizations/" + organizationID + "/incident-bulletin/intake",
				Description: "Ingest one signed counterparty federation incident bulletin for this organization.",
				Formats:     []string{"json"},
			},
		},
	}
}

func secureCellFederationIncidentResponseBundleOptions(cellID string, responseID string) securecellsintegration.SecureCellFederationIncidentResponseBundleOptions {
	cellID = strings.TrimSpace(cellID)
	responseID = strings.TrimSpace(responseID)
	return securecellsintegration.SecureCellFederationIncidentResponseBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-response-detail",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/" + responseID,
				Description: "Fetch the bilateral incident response detail for this response bundle.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-response-actions?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List response actions linked to this bilateral incident response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-response-actions/export?cell_id=" + cellID + "&response_id=" + responseID + "&format=csv",
				Description: "Export response actions linked to this bilateral incident response.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directives",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directives?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List directives and work orders linked to this bilateral incident response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directives-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directives/export?cell_id=" + cellID + "&response_id=" + responseID + "&format=csv",
				Description: "Export directives and work orders linked to this bilateral incident response.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directives-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directives/overdue?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List overdue directives and work orders linked to this bilateral incident response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-actions?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List directive lifecycle actions linked to this bilateral incident response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-actions/export?cell_id=" + cellID + "&response_id=" + responseID + "&format=csv",
				Description: "Export directive lifecycle actions linked to this bilateral incident response.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-response-remediations",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-remediations?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List remediation attestations linked to this bilateral incident response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-remediations-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-remediations/export?cell_id=" + cellID + "&response_id=" + responseID + "&format=csv",
				Description: "Export remediation attestations linked to this bilateral incident response.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-response-verifications",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-verifications?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List remediation verification records linked to this bilateral incident response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-verifications-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-verifications/export?cell_id=" + cellID + "&response_id=" + responseID + "&format=csv",
				Description: "Export remediation verification records linked to this bilateral incident response.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-response-closures",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-closures?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List closure attestations linked to this bilateral incident response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-closures-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-closures/export?cell_id=" + cellID + "&response_id=" + responseID + "&format=csv",
				Description: "Export closure attestations linked to this bilateral incident response.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-response-disputes",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-disputes?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List disputes and reopen events linked to this bilateral incident response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-response-disputes-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-disputes/export?cell_id=" + cellID + "&response_id=" + responseID + "&format=csv",
				Description: "Export disputes and reopen events linked to this bilateral incident response.",
				Formats:     []string{"json", "csv"},
			},
		},
	}
}

func secureCellFederationIncidentCasePackOptions(cellID string, responseID string) securecellsintegration.SecureCellFederationIncidentCasePackOptions {
	cellID = strings.TrimSpace(cellID)
	responseID = strings.TrimSpace(responseID)
	return securecellsintegration.SecureCellFederationIncidentCasePackOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-case-pack",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/" + responseID + "/case-pack",
				Description: "Retrieve the signed bilateral incident case pack for this response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-case-pack-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/" + responseID + "/case-pack/export?format=csv",
				Description: "Export the signed bilateral incident case pack for this response.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-response-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-responses/" + responseID + "/bundle",
				Description: "Retrieve the signed bilateral incident response bundle for this response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-reports-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-reports?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List regulator-facing incident reports for this bilateral response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-remediations-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-remediations?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List remediation attestations recorded for this bilateral response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directives-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directives?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List directives and work orders recorded for this bilateral response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-actions-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-actions?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List directive lifecycle actions recorded for this bilateral response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-automation-actions-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-automation-actions?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List automated directive escalation or contract-suspension actions recorded for this bilateral response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extensions-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extensions?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List directive deadline exception requests recorded for this bilateral response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extensions-overdue-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extensions/overdue?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List overdue directive exception reviews or disputes recorded for this bilateral response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-disputes-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-disputes?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List directive extension disputes recorded for this bilateral response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeals-overdue-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeals/overdue?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List overdue appeal-board reviews or enforcement acknowledgements for directive exception disputes on this bilateral response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-automation-actions-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-automation-actions?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List automated appeal-board delegation, escalation, or containment actions recorded for this bilateral response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-automation-actions-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-automation-actions?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List automated directive extension escalation or containment actions recorded for this bilateral response.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-disputes-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-disputes?cell_id=" + cellID + "&response_id=" + responseID,
				Description: "List disputes or reopen events recorded for this bilateral response.",
				Formats:     []string{"json"},
			},
		},
	}
}

func secureCellFederationIncidentDirectiveBundleOptions(cellID string, directiveID string) securecellsintegration.SecureCellFederationIncidentDirectiveBundleOptions {
	cellID = strings.TrimSpace(cellID)
	directiveID = strings.TrimSpace(directiveID)
	return securecellsintegration.SecureCellFederationIncidentDirectiveBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-directive-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directives?cell_id=" + cellID + "&directive_id=" + directiveID,
				Description: "List this bilateral incident directive or work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-list-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directives/export?cell_id=" + cellID + "&directive_id=" + directiveID + "&format=csv",
				Description: "Export this bilateral incident directive or work order.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-actions?cell_id=" + cellID + "&directive_id=" + directiveID,
				Description: "List directive lifecycle actions for this bilateral work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-actions/export?cell_id=" + cellID + "&directive_id=" + directiveID + "&format=csv",
				Description: "Export directive lifecycle actions for this bilateral work order.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-automation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-automation-actions?cell_id=" + cellID + "&directive_id=" + directiveID,
				Description: "List automated escalation or fail-closed actions for this bilateral work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-automation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-automation-actions/export?cell_id=" + cellID + "&directive_id=" + directiveID + "&format=csv",
				Description: "Export automated escalation or fail-closed actions for this bilateral work order.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extensions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extensions?cell_id=" + cellID + "&directive_id=" + directiveID,
				Description: "List deadline exception requests for this bilateral work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extensions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extensions/export?cell_id=" + cellID + "&directive_id=" + directiveID + "&format=csv",
				Description: "Export deadline exception requests for this bilateral work order.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extensions-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extensions/overdue?cell_id=" + cellID + "&directive_id=" + directiveID,
				Description: "List overdue deadline exception reviews or disputes for this bilateral work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extensions-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extensions/overdue/export?cell_id=" + cellID + "&directive_id=" + directiveID + "&format=csv",
				Description: "Export overdue deadline exception reviews or disputes for this bilateral work order.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-disputes",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-disputes?cell_id=" + cellID + "&directive_id=" + directiveID,
				Description: "List deadline exception disputes for this bilateral work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-disputes-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-disputes/export?cell_id=" + cellID + "&directive_id=" + directiveID + "&format=csv",
				Description: "Export deadline exception disputes for this bilateral work order.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeals?cell_id=" + cellID + "&directive_id=" + directiveID,
				Description: "List cross-organization appeal-board reviews for directive exception disputes on this bilateral work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeals-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeals/export?cell_id=" + cellID + "&directive_id=" + directiveID + "&format=csv",
				Description: "Export cross-organization appeal-board reviews for directive exception disputes on this bilateral work order.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeals-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeals/overdue?cell_id=" + cellID + "&directive_id=" + directiveID,
				Description: "List overdue appeal-board reviews or enforcement acknowledgements for this bilateral work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeals-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeals/overdue/export?cell_id=" + cellID + "&directive_id=" + directiveID + "&format=csv",
				Description: "Export overdue appeal-board reviews or enforcement acknowledgements for this bilateral work order.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-automation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-automation-actions?cell_id=" + cellID + "&directive_id=" + directiveID,
				Description: "List automated appeal-board delegation, escalation, or containment actions for this bilateral work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-automation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-automation-actions/export?cell_id=" + cellID + "&directive_id=" + directiveID + "&format=csv",
				Description: "Export automated appeal-board delegation, escalation, or containment actions for this bilateral work order.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-automation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-automation-actions?cell_id=" + cellID + "&directive_id=" + directiveID,
				Description: "List automated exception escalation or containment actions for this bilateral work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-automation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-automation-actions/export?cell_id=" + cellID + "&directive_id=" + directiveID + "&format=csv",
				Description: "Export automated exception escalation or containment actions for this bilateral work order.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directives/overdue?cell_id=" + cellID + "&directive_id=" + directiveID,
				Description: "List overdue posture for this bilateral incident directive or work order.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-detail",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directives/" + directiveID,
				Description: "Fetch the bilateral incident directive detail for this bundle.",
				Formats:     []string{"json"},
			},
		},
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealBundleOptions(cellID string, appealID string) securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealBundleOptions {
	cellID = strings.TrimSpace(cellID)
	appealID = strings.TrimSpace(appealID)
	return securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-directive-extension-appeals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeals?cell_id=" + cellID + "&appeal_id=" + appealID,
				Description: "List the bilateral appeal-board review for this directive exception dispute outcome.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeals-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeals/export?cell_id=" + cellID + "&appeal_id=" + appealID + "&format=csv",
				Description: "Export the bilateral appeal-board review for this directive exception dispute outcome.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeals-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeals/overdue?cell_id=" + cellID + "&appeal_id=" + appealID,
				Description: "List overdue board-review or enforcement acknowledgement posture for this directive exception appeal.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeals-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeals/overdue/export?cell_id=" + cellID + "&appeal_id=" + appealID + "&format=csv",
				Description: "Export overdue board-review or enforcement acknowledgement posture for this directive exception appeal.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-automation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-automation-actions?cell_id=" + cellID + "&appeal_id=" + appealID,
				Description: "List automated board-review delegation, escalation, or containment actions for this directive exception appeal.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-automation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-automation-actions/export?cell_id=" + cellID + "&appeal_id=" + appealID + "&format=csv",
				Description: "Export automated board-review delegation, escalation, or containment actions for this directive exception appeal.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeals/" + appealID + "/bundle",
				Description: "Retrieve the signed bilateral appeal bundle for this directive exception dispute outcome.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeals/" + appealID + "/bundle/export?format=csv",
				Description: "Export the signed bilateral appeal bundle for this directive exception dispute outcome.",
				Formats:     []string{"json", "csv"},
			},
		},
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleOptions(cellID string, comparisonKey string) securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleOptions {
	cellID = strings.TrimSpace(cellID)
	comparisonKey = url.PathEscape(strings.TrimSpace(comparisonKey))
	return securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-directive-extension-appeal-reconciliation-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliations?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List the bilateral appeal reconciliation state for this directive exception appeal comparison key.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-list-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliations/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export the bilateral appeal reconciliation state for this directive exception appeal comparison key.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-actions?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List governed review actions for this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-actions/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export governed review actions for this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenges",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenges?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List challenge-board reviews over this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenges-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenges/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export challenge-board reviews over this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-actions?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List challenge-board votes and rulings for this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-actions/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export challenge-board votes and rulings for this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List appeal-board reviews over ruled reconciliation challenge boards for this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeals-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export appeal-board reviews over ruled reconciliation challenge boards for this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-actions?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List appeal-board votes, rulings, and enforcement acknowledgements over reconciliation challenge boards for this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-actions/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export appeal-board votes, rulings, and enforcement acknowledgements over reconciliation challenge boards for this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-recusals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-recusals?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List reviewer recusals and rehearing lineage over reconciliation challenge appeal boards for this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-recusals-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-recusals/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export reviewer recusals and rehearing lineage over reconciliation challenge appeal boards for this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenges-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenges/overdue?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List overdue challenge-board reviews for this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenges-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenges/overdue/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export overdue challenge-board reviews for this bilateral directive exception appeal reconciliation.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-automation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-automation-actions?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List automated delegation, escalation, and containment actions for this bilateral directive exception appeal reconciliation challenge board.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-automation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-automation-actions/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export automated delegation, escalation, and containment actions for this bilateral directive exception appeal reconciliation challenge board.",
				Formats:     []string{"json", "csv"},
			},
		},
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleOptions(cellID string, challengeAppealID string) securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleOptions {
	cellID = strings.TrimSpace(cellID)
	queryChallengeAppealID := url.QueryEscape(strings.TrimSpace(challengeAppealID))
	pathChallengeAppealID := url.PathEscape(strings.TrimSpace(challengeAppealID))
	return securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List the governed reconciliation challenge-appeal board state for this bilateral directive exception appeal path.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeals-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export the governed reconciliation challenge-appeal board state for this bilateral directive exception appeal path.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-actions?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List appeal-board votes, rulings, and enforcement acknowledgements for this reconciliation challenge appeal.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-actions/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export appeal-board votes, rulings, and enforcement acknowledgements for this reconciliation challenge appeal.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignments-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignments/overdue?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List overdue reciprocal challenge-appeal alignment review posture for this reconciliation challenge appeal.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignments-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignments/overdue/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export overdue reciprocal challenge-appeal alignment review posture for this reconciliation challenge appeal.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-automation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-automation-actions?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List automated escalation or contract-suspension actions taken for reciprocal challenge-appeal alignment review.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-automation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-automation-actions/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export automated escalation or contract-suspension actions taken for reciprocal challenge-appeal alignment review.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-recusals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-recusals?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List reviewer recusals and rehearing lineage for this reconciliation challenge appeal.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-recusals-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-recusals/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export reviewer recusals and rehearing lineage for this reconciliation challenge appeal.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeals-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/overdue?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List overdue board-review or enforcement-acknowledgement posture for this reconciliation challenge appeal.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeals-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/overdue/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export overdue board-review or enforcement-acknowledgement posture for this reconciliation challenge appeal.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-automation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-automation-actions?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List automated delegation, escalation, and containment actions for this reconciliation challenge appeal board.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-automation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-automation-actions/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export automated delegation, escalation, and containment actions for this reconciliation challenge appeal board.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeals?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List imported reciprocal challenge-appeal bundles aligned to this reconciliation challenge appeal.",
				Formats:     []string{"json"},
			},
			{
				ID:          "counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeals-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeals/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export imported reciprocal challenge-appeal bundles aligned to this reconciliation challenge appeal.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-actions?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List governed acknowledgements or disputes over imported reciprocal challenge-appeal bundles for this appeal-board trail.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-actions/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export governed acknowledgements or disputes over imported reciprocal challenge-appeal bundles for this appeal-board trail.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-actions?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List governed responses to automated reciprocal challenge-appeal alignment actions for this appeal-board trail.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-actions/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export governed responses to automated reciprocal challenge-appeal alignment actions for this appeal-board trail.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List governed correction-board appeals over bilateral alignment-response actions for this appeal-board trail.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export governed correction-board appeals over bilateral alignment-response actions for this appeal-board trail.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-actions?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List correction-board action trails over bilateral alignment-response appeals for this appeal-board trail.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-actions/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export correction-board action trails over bilateral alignment-response appeals for this appeal-board trail.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/" + pathChallengeAppealID + "/alignment-response/bundle",
				Description: "Retrieve the signed bilateral alignment-response bundle for this appeal-board trail.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/" + pathChallengeAppealID + "/alignment-response/bundle/export?format=csv",
				Description: "Export the signed bilateral alignment-response bundle for this appeal-board trail.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/" + pathChallengeAppealID + "/bundle",
				Description: "Retrieve the signed bilateral reconciliation challenge-appeal bundle for this appeal-board ruling path.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/" + pathChallengeAppealID + "/bundle/export?format=csv",
				Description: "Export the signed bilateral reconciliation challenge-appeal bundle for this appeal-board ruling path.",
				Formats:     []string{"json", "csv"},
			},
		},
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleOptions(cellID string, challengeAppealID string) securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleOptions {
	cellID = strings.TrimSpace(cellID)
	queryChallengeAppealID := url.QueryEscape(strings.TrimSpace(challengeAppealID))
	pathChallengeAppealID := url.PathEscape(strings.TrimSpace(challengeAppealID))
	return securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-actions?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List governed acknowledgements or disputes over imported reciprocal challenge-appeal bundles for this appeal-board trail.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-actions/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export governed acknowledgements or disputes over imported reciprocal challenge-appeal bundles for this appeal-board trail.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-automation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-automation-actions?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List automated escalation or contract-suspension actions taken for reciprocal challenge-appeal alignment review.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-automation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-automation-actions/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export automated escalation or contract-suspension actions taken for reciprocal challenge-appeal alignment review.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-actions?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List governed responses to automated reciprocal challenge-appeal alignment actions for this appeal-board trail.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-actions/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export governed responses to automated reciprocal challenge-appeal alignment actions for this appeal-board trail.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List governed correction-board appeals over bilateral alignment-response actions for this appeal-board trail.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeals/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export governed correction-board appeals over bilateral alignment-response actions for this appeal-board trail.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-actions?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID,
				Description: "List correction-board action trails over bilateral alignment-response appeals for this appeal-board trail.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-actions/export?cell_id=" + cellID + "&challenge_appeal_id=" + queryChallengeAppealID + "&format=csv",
				Description: "Export correction-board action trails over bilateral alignment-response appeals for this appeal-board trail.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/" + pathChallengeAppealID + "/alignment-response/bundle",
				Description: "Retrieve the signed bilateral alignment-response bundle for this appeal-board trail.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeals/" + pathChallengeAppealID + "/alignment-response/bundle/export?format=csv",
				Description: "Export the signed bilateral alignment-response bundle for this appeal-board trail.",
				Formats:     []string{"json", "csv"},
			},
		},
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleOptions(cellID string, reviewID string) securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleOptions {
	cellID = strings.TrimSpace(cellID)
	queryReviewID := url.QueryEscape(strings.TrimSpace(reviewID))
	pathReviewID := url.PathEscape(strings.TrimSpace(reviewID))
	return securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-reviews",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-reviews?cell_id=" + cellID + "&review_id=" + queryReviewID,
				Description: "List bilateral review chains over imported counterparty correction-board rulings for this review path.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-reviews-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-reviews/export?cell_id=" + cellID + "&review_id=" + queryReviewID + "&format=csv",
				Description: "Export bilateral review chains over imported counterparty correction-board rulings for this review path.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-reviews/" + pathReviewID + "/bundle",
				Description: "Retrieve the signed bilateral review bundle for this imported counterparty correction-board ruling review path.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-reviews/" + pathReviewID + "/bundle/export?format=csv",
				Description: "Export the signed bilateral review bundle for this imported counterparty correction-board ruling review path.",
				Formats:     []string{"json", "csv"},
			},
		},
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleOptions(cellID string, appealReviewID string) securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleOptions {
	cellID = strings.TrimSpace(cellID)
	queryAppealReviewID := url.QueryEscape(strings.TrimSpace(appealReviewID))
	pathAppealReviewID := url.PathEscape(strings.TrimSpace(appealReviewID))
	return securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals?cell_id=" + cellID + "&appeal_review_id=" + queryAppealReviewID,
				Description: "List first-class bilateral rehearing boards opened from imported counterparty correction-board ruling disputes.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals/export?cell_id=" + cellID + "&appeal_review_id=" + queryAppealReviewID + "&format=csv",
				Description: "Export first-class bilateral rehearing boards opened from imported counterparty correction-board ruling disputes.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals/" + pathAppealReviewID + "/bundle",
				Description: "Retrieve the signed bilateral rehearing-board bundle for this imported counterparty ruling dispute path.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals/" + pathAppealReviewID + "/bundle/export?format=csv",
				Description: "Export the signed bilateral rehearing-board bundle for this imported counterparty ruling dispute path.",
				Formats:     []string{"json", "csv"},
			},
		},
	}
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleOptions(cellID string, snapshotID string) securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleOptions {
	cellID = strings.TrimSpace(cellID)
	querySnapshotID := url.QueryEscape(strings.TrimSpace(snapshotID))
	pathSnapshotID := url.PathEscape(strings.TrimSpace(snapshotID))
	return securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals?cell_id=" + cellID + "&snapshot_id=" + querySnapshotID,
				Description: "List imported reciprocal rehearing-board bundles for this governed review trail.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-actions?cell_id=" + cellID + "&snapshot_id=" + querySnapshotID,
				Description: "List governed review actions over this imported reciprocal rehearing-board bundle.",
				Formats:     []string{"json"},
			},
			{
				ID:          "counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals/" + pathSnapshotID + "/review-bundle",
				Description: "Retrieve the signed bilateral review bundle for this imported reciprocal rehearing-board bundle.",
				Formats:     []string{"json"},
			},
			{
				ID:          "counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals/" + pathSnapshotID + "/review-bundle/export?format=csv",
				Description: "Export the signed bilateral review bundle for this imported reciprocal rehearing-board bundle.",
				Formats:     []string{"json", "csv"},
			},
		},
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleOptions(cellID string, responseAppealID string) securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleOptions {
	cellID = strings.TrimSpace(cellID)
	queryResponseAppealID := url.QueryEscape(strings.TrimSpace(responseAppealID))
	pathResponseAppealID := url.PathEscape(strings.TrimSpace(responseAppealID))
	return securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals?cell_id=" + cellID + "&response_appeal_id=" + queryResponseAppealID,
				Description: "List first-class rehearing boards opened from disputed imported reciprocal appeal-board review trails.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals/export?cell_id=" + cellID + "&response_appeal_id=" + queryResponseAppealID + "&format=csv",
				Description: "Export first-class rehearing boards opened from disputed imported reciprocal appeal-board review trails.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-actions?cell_id=" + cellID + "&response_appeal_id=" + queryResponseAppealID,
				Description: "List governed local acknowledgement and dispute actions over imported reciprocal rehearing-board rulings for this response appeal.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-actions/export?cell_id=" + cellID + "&response_appeal_id=" + queryResponseAppealID + "&format=csv",
				Description: "Export governed local acknowledgement and dispute actions over imported reciprocal rehearing-board rulings for this response appeal.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals/" + pathResponseAppealID + "/bundle",
				Description: "Retrieve the signed bilateral rehearing-board bundle opened from this imported reciprocal appeal-board review trail.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals/" + pathResponseAppealID + "/bundle/export?format=csv",
				Description: "Export the signed bilateral rehearing-board bundle opened from this imported reciprocal appeal-board review trail.",
				Formats:     []string{"json", "csv"},
			},
		},
	}
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleOptions(cellID string, snapshotID string) securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleOptions {
	cellID = strings.TrimSpace(cellID)
	querySnapshotID := url.QueryEscape(strings.TrimSpace(snapshotID))
	pathSnapshotID := url.PathEscape(strings.TrimSpace(snapshotID))
	return securecellsintegration.SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals?cell_id=" + cellID + "&snapshot_id=" + querySnapshotID,
				Description: "List imported reciprocal rehearing-board bundles for this governed review trail.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-actions?cell_id=" + cellID + "&snapshot_id=" + querySnapshotID,
				Description: "List governed review actions over this imported reciprocal rehearing-board bundle.",
				Formats:     []string{"json"},
			},
			{
				ID:          "counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals/" + pathSnapshotID + "/review-bundle",
				Description: "Retrieve the signed bilateral review bundle for this imported reciprocal rehearing-board bundle.",
				Formats:     []string{"json"},
			},
			{
				ID:          "counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundle-export",
				Method:      http.MethodGet,
				Path:        secureCellsItemPrefix + cellID + "/federation/counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals/" + pathSnapshotID + "/review-bundle/export?format=csv",
				Description: "Export the signed bilateral review bundle for this imported reciprocal rehearing-board bundle.",
				Formats:     []string{"json", "csv"},
			},
		},
	}
}

func secureCellFederationIncidentReportBundleOptions(cellID string, reportID string) securecellsintegration.SecureCellFederationIncidentReportBundleOptions {
	cellID = strings.TrimSpace(cellID)
	reportID = strings.TrimSpace(reportID)
	return securecellsintegration.SecureCellFederationIncidentReportBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-report-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-reports?cell_id=" + cellID + "&report_id=" + reportID,
				Description: "List this governed cross-org incident reporting obligation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-list-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-reports/export?cell_id=" + cellID + "&report_id=" + reportID + "&format=csv",
				Description: "Export this governed cross-org incident reporting obligation.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-report-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-reports/overdue?cell_id=" + cellID,
				Description: "List overdue governed cross-org incident reporting obligations for this secure cell.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-reports/overdue/export?cell_id=" + cellID + "&format=csv",
				Description: "Export overdue governed cross-org incident reporting obligations for this secure cell.",
				Formats:     []string{"json", "csv"},
			},
		},
	}
}

func secureCellFederationIncidentReportAmendmentBundleOptions(cellID string, amendmentID string) securecellsintegration.SecureCellFederationIncidentReportAmendmentBundleOptions {
	cellID = strings.TrimSpace(cellID)
	amendmentID = strings.TrimSpace(amendmentID)
	return securecellsintegration.SecureCellFederationIncidentReportAmendmentBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-report-amendment-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendments?cell_id=" + cellID + "&amendment_id=" + amendmentID,
				Description: "List governed amendments for this incident-report amendment ID.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-amendment-list-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendments/export?cell_id=" + cellID + "&amendment_id=" + amendmentID + "&format=csv",
				Description: "Export governed amendments for this incident-report amendment ID.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-report-amendment-submit",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-report-amendments/{amendment_id}/submit",
				Description: "Submit one governed incident-report amendment.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-amendment-acknowledge",
				Method:      http.MethodPost,
				Path:        secureCellsItemPrefix + cellID + "/federation/incident-report-amendments/{amendment_id}/acknowledge",
				Description: "Acknowledge one governed incident-report amendment.",
				Formats:     []string{"json"},
			},
		},
	}
}

func secureCellFederationIncidentReportReconciliationBundleOptions(cellID string, comparisonKey string) securecellsintegration.SecureCellFederationIncidentReportReconciliationBundleOptions {
	cellID = strings.TrimSpace(cellID)
	comparisonKey = url.PathEscape(strings.TrimSpace(comparisonKey))
	return securecellsintegration.SecureCellFederationIncidentReportReconciliationBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-report-reconciliation-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-reconciliations?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List the bilateral incident-report reconciliation state for this comparison key.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-reconciliation-list-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-reconciliations/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export the bilateral incident-report reconciliation state for this comparison key.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-report-reconciliation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-reconciliation-actions?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List governed review actions for this bilateral incident-report reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-reconciliation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-reconciliation-actions/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export governed review actions for this bilateral incident-report reconciliation.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-report-reconciliation-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-reconciliations/overdue?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List overdue review or dispute-resolution milestones for this bilateral incident-report reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-reconciliation-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-reconciliations/overdue/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export overdue review or dispute-resolution milestones for this bilateral incident-report reconciliation.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-report-reconciliation-automation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-reconciliation-automation-actions?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List automated protective actions applied to this bilateral incident-report reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-reconciliation-automation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-reconciliation-automation-actions/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export automated protective actions applied to this bilateral incident-report reconciliation.",
				Formats:     []string{"json", "csv"},
			},
		},
	}
}

func secureCellFederationIncidentReportAmendmentReconciliationBundleOptions(cellID string, comparisonKey string) securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationBundleOptions {
	cellID = strings.TrimSpace(cellID)
	comparisonKey = url.PathEscape(strings.TrimSpace(comparisonKey))
	return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationBundleOptions{
		OperatorSurfaces: []securecellsintegration.SecureCellFederationOperatorSurface{
			{
				ID:          "incident-report-amendment-reconciliation-list",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliations?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List the bilateral incident-report amendment reconciliation state for this comparison key.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-amendment-reconciliation-list-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliations/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export the bilateral incident-report amendment reconciliation state for this comparison key.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-report-amendment-reconciliation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliation-actions?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List governed review actions for this bilateral incident-report amendment reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-amendment-reconciliation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliation-actions/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export governed review actions for this bilateral incident-report amendment reconciliation.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-report-amendment-reconciliation-attestations",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliation-attestations?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List counterparty acknowledgements and correction or resolution attestations for this bilateral incident-report amendment reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-amendment-reconciliation-attestations-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliation-attestations/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export counterparty acknowledgements and correction or resolution attestations for this bilateral incident-report amendment reconciliation.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-report-amendment-reconciliation-overdue",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliations/overdue?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List overdue review, counterparty acknowledgement, or dispute-resolution milestones for this bilateral incident-report amendment reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-amendment-reconciliation-overdue-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliations/overdue/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export overdue review, counterparty acknowledgement, or dispute-resolution milestones for this bilateral incident-report amendment reconciliation.",
				Formats:     []string{"json", "csv"},
			},
			{
				ID:          "incident-report-amendment-reconciliation-automation-actions",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliation-automation-actions?cell_id=" + cellID + "&comparison_key=" + comparisonKey,
				Description: "List automated escalation or containment actions applied to this bilateral incident-report amendment reconciliation.",
				Formats:     []string{"json"},
			},
			{
				ID:          "incident-report-amendment-reconciliation-automation-actions-export",
				Method:      http.MethodGet,
				Path:        secureCellsCollectionRoute + "/federation/incident-report-amendment-reconciliation-automation-actions/export?cell_id=" + cellID + "&comparison_key=" + comparisonKey + "&format=csv",
				Description: "Export automated escalation or containment actions applied to this bilateral incident-report amendment reconciliation.",
				Formats:     []string{"json", "csv"},
			},
		},
	}
}

func secureCellDecisionVoteChoiceAllowed(raw string) bool {
	switch securecellsintegration.SecureCellThreadDecisionVoteChoice(strings.ToLower(strings.TrimSpace(raw))) {
	case securecellsintegration.SecureCellThreadDecisionVoteChoiceApprove,
		securecellsintegration.SecureCellThreadDecisionVoteChoiceReject,
		securecellsintegration.SecureCellThreadDecisionVoteChoiceAbstain:
		return true
	default:
		return false
	}
}

func secureCellDecisionFromResult(result *securecellsintegration.SecureCellResult, sessionID string, threadID string, decisionID string) (*securecellsintegration.SecureCellThreadDecision, bool) {
	if result == nil {
		return nil, false
	}
	for _, decision := range result.Decisions {
		if strings.TrimSpace(decision.SessionID) != strings.TrimSpace(sessionID) {
			continue
		}
		if strings.TrimSpace(decision.ThreadID) != strings.TrimSpace(threadID) {
			continue
		}
		if strings.TrimSpace(decision.ID) != strings.TrimSpace(decisionID) {
			continue
		}
		clone := decision
		return &clone, true
	}
	return nil, false
}

func secureCellDecisionsForThread(result *securecellsintegration.SecureCellResult, sessionID string, threadID string) []securecellsintegration.SecureCellThreadDecision {
	if result == nil {
		return nil
	}
	items := make([]securecellsintegration.SecureCellThreadDecision, 0)
	for _, decision := range result.Decisions {
		if strings.TrimSpace(decision.SessionID) != strings.TrimSpace(sessionID) {
			continue
		}
		if strings.TrimSpace(decision.ThreadID) != strings.TrimSpace(threadID) {
			continue
		}
		items = append(items, decision)
	}
	return items
}

func secureCellDecisionDeliberationProjection(result *securecellsintegration.SecureCellResult, sessionID string, threadID string, decisionID string) (secureCellDecisionDeliberationResponse, bool) {
	decision, ok := secureCellDecisionFromResult(result, sessionID, threadID, decisionID)
	if !ok {
		return secureCellDecisionDeliberationResponse{}, false
	}
	return secureCellDecisionDeliberationResponse{
		Result:           decision,
		DecisionOutcomes: secureCellDecisionOutcomesForDecision(result, decision),
		SharedOutputs:    secureCellSharedOutputsForDecision(result, decision),
		SessionExchanges: secureCellSessionExchangesForDecision(result, decision),
	}, true
}

func secureCellDecisionOutcomesForDecision(result *securecellsintegration.SecureCellResult, decision *securecellsintegration.SecureCellThreadDecision) []securecellsintegration.SecureCellThreadDecisionOutcome {
	if result == nil || decision == nil {
		return nil
	}
	decisionID := strings.TrimSpace(decision.ID)
	if decisionID == "" {
		return nil
	}
	items := make([]securecellsintegration.SecureCellThreadDecisionOutcome, 0)
	for _, outcome := range result.DecisionOutcomes {
		if strings.TrimSpace(outcome.DecisionID) == decisionID {
			items = append(items, outcome)
		}
	}
	return items
}

func secureCellSharedOutputsForDecision(result *securecellsintegration.SecureCellResult, decision *securecellsintegration.SecureCellThreadDecision) []securecellsintegration.SecureCellSharedOutput {
	if result == nil || decision == nil {
		return nil
	}
	decisionID := strings.TrimSpace(decision.ID)
	if decisionID == "" {
		return nil
	}
	items := make([]securecellsintegration.SecureCellSharedOutput, 0)
	for _, output := range result.SharedOutputs {
		if strings.TrimSpace(output.ContainmentDecisionID) == decisionID || containsString(decision.RelatedOutputIDs, output.ID) {
			items = append(items, output)
		}
	}
	return items
}

func secureCellSessionExchangesForDecision(result *securecellsintegration.SecureCellResult, decision *securecellsintegration.SecureCellThreadDecision) []securecellsintegration.SecureCellSessionExchange {
	if result == nil || decision == nil {
		return nil
	}
	decisionID := strings.TrimSpace(decision.ID)
	if decisionID == "" {
		return nil
	}
	items := make([]securecellsintegration.SecureCellSessionExchange, 0)
	for _, exchange := range result.SessionExchanges {
		if strings.TrimSpace(exchange.ContainmentDecisionID) == decisionID || containsString(decision.RelatedExchangeIDs, exchange.ID) {
			items = append(items, exchange)
		}
	}
	return items
}

func derefSecureCellTime(in *time.Time) time.Time {
	if in == nil {
		return time.Time{}
	}
	return in.UTC()
}

func parseSecureCellListFilter(r *http.Request) (securecellsintegration.SecureCellListFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellListFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	statuses, err := parseSecureCellStatuses(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellListFilter{}, err
	}
	updatedAfter, err := parseSecureCellOptionalTime(query.Get("updated_after"))
	if err != nil {
		return securecellsintegration.SecureCellListFilter{}, err
	}
	updatedBefore, err := parseSecureCellOptionalTime(query.Get("updated_before"))
	if err != nil {
		return securecellsintegration.SecureCellListFilter{}, err
	}
	return securecellsintegration.SecureCellListFilter{
		Statuses:       statuses,
		Jurisdiction:   strings.TrimSpace(query.Get("jurisdiction")),
		ParticipantDID: strings.TrimSpace(query.Get("participant_did")),
		UpdatedAfter:   updatedAfter,
		UpdatedBefore:  updatedBefore,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationOrganizationFilter(r *http.Request) (securecellsintegration.SecureCellFederationOrganizationFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationOrganizationFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	status, err := parseSecureCellFederationOrganizationStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationOrganizationFilter{}, err
	}
	updatedAfter, err := parseSecureCellOptionalTime(query.Get("updated_after"))
	if err != nil {
		return securecellsintegration.SecureCellFederationOrganizationFilter{}, err
	}
	updatedBefore, err := parseSecureCellOptionalTime(query.Get("updated_before"))
	if err != nil {
		return securecellsintegration.SecureCellFederationOrganizationFilter{}, err
	}
	return securecellsintegration.SecureCellFederationOrganizationFilter{
		CellID:          strings.TrimSpace(query.Get("cell_id")),
		Status:          status,
		Jurisdiction:    strings.TrimSpace(query.Get("jurisdiction")),
		SponsorOfRecord: strings.TrimSpace(query.Get("sponsor_of_record")),
		ParticipantDID:  strings.TrimSpace(query.Get("participant_did")),
		UpdatedAfter:    updatedAfter,
		UpdatedBefore:   updatedBefore,
		Limit:           cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationInvitationFilter(r *http.Request) (securecellsintegration.SecureCellFederationInvitationFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationInvitationFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	status, err := parseSecureCellFederationInvitationStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationInvitationFilter{}, err
	}
	updatedAfter, err := parseSecureCellOptionalTime(query.Get("updated_after"))
	if err != nil {
		return securecellsintegration.SecureCellFederationInvitationFilter{}, err
	}
	updatedBefore, err := parseSecureCellOptionalTime(query.Get("updated_before"))
	if err != nil {
		return securecellsintegration.SecureCellFederationInvitationFilter{}, err
	}
	return securecellsintegration.SecureCellFederationInvitationFilter{
		CellID:          strings.TrimSpace(query.Get("cell_id")),
		OrganizationID:  strings.TrimSpace(query.Get("organization_id")),
		Status:          status,
		Jurisdiction:    strings.TrimSpace(query.Get("jurisdiction")),
		SponsorOfRecord: strings.TrimSpace(query.Get("sponsor_of_record")),
		ExpectedDID:     strings.TrimSpace(query.Get("expected_did")),
		UpdatedAfter:    updatedAfter,
		UpdatedBefore:   updatedBefore,
		Limit:           cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationContractFilter(r *http.Request) (securecellsintegration.SecureCellFederationContractFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationContractFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	status, err := parseSecureCellFederationContractStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationContractFilter{}, err
	}
	updatedAfter, err := parseSecureCellOptionalTime(query.Get("updated_after"))
	if err != nil {
		return securecellsintegration.SecureCellFederationContractFilter{}, err
	}
	updatedBefore, err := parseSecureCellOptionalTime(query.Get("updated_before"))
	if err != nil {
		return securecellsintegration.SecureCellFederationContractFilter{}, err
	}
	return securecellsintegration.SecureCellFederationContractFilter{
		CellID:          strings.TrimSpace(query.Get("cell_id")),
		OrganizationID:  strings.TrimSpace(query.Get("organization_id")),
		Status:          status,
		SponsorOfRecord: strings.TrimSpace(query.Get("sponsor_of_record")),
		ParticipantDID:  strings.TrimSpace(query.Get("participant_did")),
		SessionID:       strings.TrimSpace(query.Get("session_id")),
		Action:          strings.TrimSpace(query.Get("action")),
		Classification:  strings.TrimSpace(query.Get("classification")),
		UpdatedAfter:    updatedAfter,
		UpdatedBefore:   updatedBefore,
		Limit:           cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationCounterproposalFilter(r *http.Request) (securecellsintegration.SecureCellFederationCounterproposalFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationCounterproposalFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	status, err := parseSecureCellFederationCounterproposalStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationCounterproposalFilter{}, err
	}
	updatedAfter, err := parseSecureCellOptionalTime(query.Get("updated_after"))
	if err != nil {
		return securecellsintegration.SecureCellFederationCounterproposalFilter{}, err
	}
	updatedBefore, err := parseSecureCellOptionalTime(query.Get("updated_before"))
	if err != nil {
		return securecellsintegration.SecureCellFederationCounterproposalFilter{}, err
	}
	return securecellsintegration.SecureCellFederationCounterproposalFilter{
		CellID:          strings.TrimSpace(query.Get("cell_id")),
		OrganizationID:  strings.TrimSpace(query.Get("organization_id")),
		InvitationID:    strings.TrimSpace(query.Get("invitation_id")),
		Status:          status,
		SponsorOfRecord: strings.TrimSpace(query.Get("sponsor_of_record")),
		SubmittedBy:     strings.TrimSpace(query.Get("submitted_by")),
		UpdatedAfter:    updatedAfter,
		UpdatedBefore:   updatedBefore,
		Limit:           cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellOverdueFederationCounterproposalFilter(r *http.Request) (securecellsintegration.SecureCellOverdueFederationCounterproposalFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellOverdueFederationCounterproposalFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	before, err := parseSecureCellOptionalTime(query.Get("before"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueFederationCounterproposalFilter{}, err
	}
	return securecellsintegration.SecureCellOverdueFederationCounterproposalFilter{
		CellID:          strings.TrimSpace(query.Get("cell_id")),
		OrganizationID:  strings.TrimSpace(query.Get("organization_id")),
		InvitationID:    strings.TrimSpace(query.Get("invitation_id")),
		SponsorOfRecord: strings.TrimSpace(query.Get("sponsor_of_record")),
		SubmittedBy:     strings.TrimSpace(query.Get("submitted_by")),
		Before:          before,
		Limit:           cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationAutomationActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationAutomationActionFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationAutomationActionFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellFederationAutomationActionFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellFederationAutomationActionFilter{}, err
	}
	return securecellsintegration.SecureCellFederationAutomationActionFilter{
		CellID:            strings.TrimSpace(query.Get("cell_id")),
		OrganizationID:    strings.TrimSpace(query.Get("organization_id")),
		InvitationID:      strings.TrimSpace(query.Get("invitation_id")),
		CounterproposalID: strings.TrimSpace(query.Get("counterproposal_id")),
		ContractID:        strings.TrimSpace(query.Get("contract_id")),
		Action:            strings.TrimSpace(query.Get("action")),
		Since:             since,
		Until:             until,
		Limit:             cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationAssuranceFilter(r *http.Request) (securecellsintegration.SecureCellFederationAssuranceFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationAssuranceFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	severity, err := parseSecureCellFederationAssuranceSeverity(query.Get("severity"))
	if err != nil {
		return securecellsintegration.SecureCellFederationAssuranceFilter{}, err
	}
	category, err := parseSecureCellFederationAssuranceCategory(query.Get("category"))
	if err != nil {
		return securecellsintegration.SecureCellFederationAssuranceFilter{}, err
	}
	return securecellsintegration.SecureCellFederationAssuranceFilter{
		CellID:          strings.TrimSpace(query.Get("cell_id")),
		OrganizationID:  strings.TrimSpace(query.Get("organization_id")),
		ContractID:      strings.TrimSpace(query.Get("contract_id")),
		SponsorOfRecord: strings.TrimSpace(query.Get("sponsor_of_record")),
		ParticipantDID:  strings.TrimSpace(query.Get("participant_did")),
		Severity:        severity,
		Category:        category,
		Limit:           cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationAssuranceActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationAssuranceActionFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationAssuranceActionFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellFederationAssuranceActionFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellFederationAssuranceActionFilter{}, err
	}
	return securecellsintegration.SecureCellFederationAssuranceActionFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		ContractID:     strings.TrimSpace(query.Get("contract_id")),
		FindingID:      strings.TrimSpace(query.Get("finding_id")),
		Category:       strings.TrimSpace(query.Get("category")),
		Since:          since,
		Until:          until,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationCounterpartyAssuranceFilter(r *http.Request) (securecellsintegration.SecureCellFederationCounterpartyAssuranceFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationCounterpartyAssuranceFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	status, err := parseSecureCellFederationCounterpartyAssuranceStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationCounterpartyAssuranceFilter{}, err
	}
	return securecellsintegration.SecureCellFederationCounterpartyAssuranceFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		ContractID:     strings.TrimSpace(query.Get("contract_id")),
		Status:         status,
		Signer:         strings.TrimSpace(query.Get("signer")),
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	status, err := parseSecureCellFederationIncidentStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentFilter{}, err
	}
	severity, err := parseSecureCellFederationIncidentSeverity(query.Get("severity"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentFilter{}, err
	}
	category, err := parseSecureCellFederationIncidentCategory(query.Get("category"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentFilter{}, err
	}
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		ContractID:     strings.TrimSpace(query.Get("contract_id")),
		Status:         status,
		Severity:       severity,
		Category:       category,
		Since:          since,
		Until:          until,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentActionFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentActionFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentActionFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentActionFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentActionFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		ContractID:     strings.TrimSpace(query.Get("contract_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		Action:         strings.TrimSpace(query.Get("action")),
		Since:          since,
		Until:          until,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentResponseFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentResponseFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentResponseFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	status, err := parseSecureCellFederationIncidentResponseStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentResponseFilter{}, err
	}
	sourceType, err := parseSecureCellFederationIncidentResponseSource(query.Get("source_type"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentResponseFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentResponseFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ResponseID:     strings.TrimSpace(query.Get("response_id")),
		ContractID:     strings.TrimSpace(query.Get("contract_id")),
		Status:         status,
		SourceType:     sourceType,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellOverdueFederationIncidentResponseFilter(r *http.Request) (securecellsintegration.SecureCellOverdueFederationIncidentResponseFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellOverdueFederationIncidentResponseFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	before, err := parseSecureCellOptionalTime(query.Get("before"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueFederationIncidentResponseFilter{}, err
	}
	return securecellsintegration.SecureCellOverdueFederationIncidentResponseFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ResponseID:     strings.TrimSpace(query.Get("response_id")),
		ContractID:     strings.TrimSpace(query.Get("contract_id")),
		Before:         before,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentResponseActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentResponseActionFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentResponseActionFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentResponseActionFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentResponseActionFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentResponseActionFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ResponseID:     strings.TrimSpace(query.Get("response_id")),
		ContractID:     strings.TrimSpace(query.Get("contract_id")),
		Action:         strings.TrimSpace(query.Get("action")),
		Since:          since,
		Until:          until,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentReportFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentReportFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentReportFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	reportingParty, err := parseSecureCellFederationIncidentResponseParty(query.Get("reporting_party"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportFilter{}, err
	}
	status, err := parseSecureCellFederationIncidentReportStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportFilter{}, err
	}
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentReportFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ResponseID:     strings.TrimSpace(query.Get("response_id")),
		ReportID:       strings.TrimSpace(query.Get("report_id")),
		ReportingParty: reportingParty,
		Status:         status,
		Regulator:      strings.TrimSpace(query.Get("regulator")),
		Since:          since,
		Until:          until,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentReportAmendmentFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentReportAmendmentFilter, error) {
	query := r.URL.Query()
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentReportAmendmentFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ResponseID:     strings.TrimSpace(query.Get("response_id")),
		ReportID:       strings.TrimSpace(query.Get("report_id")),
		AmendmentID:    strings.TrimSpace(query.Get("amendment_id")),
		Status:         securecellsintegration.SecureCellFederationIncidentReportAmendmentStatus(strings.TrimSpace(query.Get("status"))),
		Regulator:      strings.TrimSpace(query.Get("regulator")),
		Since:          since,
		Until:          until,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellOverdueFederationIncidentReportFilter(r *http.Request) (securecellsintegration.SecureCellOverdueFederationIncidentReportFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellOverdueFederationIncidentReportFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	before, err := parseSecureCellOptionalTime(query.Get("before"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueFederationIncidentReportFilter{}, err
	}
	return securecellsintegration.SecureCellOverdueFederationIncidentReportFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ResponseID:     strings.TrimSpace(query.Get("response_id")),
		Regulator:      strings.TrimSpace(query.Get("regulator")),
		Before:         before,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellOverdueFederationIncidentReportReconciliationFilter(r *http.Request) (securecellsintegration.SecureCellOverdueFederationIncidentReportReconciliationFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellOverdueFederationIncidentReportReconciliationFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	before, err := parseSecureCellOptionalTime(query.Get("before"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueFederationIncidentReportReconciliationFilter{}, err
	}
	status, err := parseSecureCellFederationIncidentReportReconciliationStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueFederationIncidentReportReconciliationFilter{}, err
	}
	reviewStatus, err := parseSecureCellFederationIncidentReportReviewStatus(query.Get("review_status"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueFederationIncidentReportReconciliationFilter{}, err
	}
	return securecellsintegration.SecureCellOverdueFederationIncidentReportReconciliationFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ComparisonKey:  strings.TrimSpace(query.Get("comparison_key")),
		Status:         status,
		ReviewStatus:   reviewStatus,
		Before:         before,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentReportReconciliationAutomationActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentReportReconciliationAutomationActionFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationAutomationActionFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationAutomationActionFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationAutomationActionFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentReportReconciliationAutomationActionFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ComparisonKey:  strings.TrimSpace(query.Get("comparison_key")),
		ContractID:     strings.TrimSpace(query.Get("contract_id")),
		Action:         strings.TrimSpace(query.Get("action")),
		Since:          since,
		Until:          until,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentRemediationFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentRemediationFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentRemediationFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	attestingParty, err := parseSecureCellFederationIncidentResponseParty(query.Get("attesting_party"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentRemediationFilter{}, err
	}
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentRemediationFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentRemediationFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentRemediationFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ResponseID:     strings.TrimSpace(query.Get("response_id")),
		AttestingParty: attestingParty,
		Since:          since,
		Until:          until,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentVerificationFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentVerificationFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentVerificationFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	reviewingParty, err := parseSecureCellFederationIncidentResponseParty(query.Get("reviewing_party"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentVerificationFilter{}, err
	}
	decision, err := parseSecureCellFederationIncidentRemediationVerificationDecision(query.Get("decision"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentVerificationFilter{}, err
	}
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentVerificationFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentVerificationFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentVerificationFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ResponseID:     strings.TrimSpace(query.Get("response_id")),
		ReviewingParty: reviewingParty,
		Decision:       decision,
		Since:          since,
		Until:          until,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentClosureAttestationFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentClosureAttestationFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentClosureAttestationFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	attestingParty, err := parseSecureCellFederationIncidentResponseParty(query.Get("attesting_party"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentClosureAttestationFilter{}, err
	}
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentClosureAttestationFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentClosureAttestationFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentClosureAttestationFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ResponseID:     strings.TrimSpace(query.Get("response_id")),
		AttestingParty: attestingParty,
		Since:          since,
		Until:          until,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentDisputeFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentDisputeFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentDisputeFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	disputingParty, err := parseSecureCellFederationIncidentResponseParty(query.Get("disputing_party"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentDisputeFilter{}, err
	}
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentDisputeFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentDisputeFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentDisputeFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ResponseID:     strings.TrimSpace(query.Get("response_id")),
		DisputingParty: disputingParty,
		Since:          since,
		Until:          until,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationCounterpartyIncidentFilter(r *http.Request) (securecellsintegration.SecureCellFederationCounterpartyIncidentFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationCounterpartyIncidentFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	status, err := parseSecureCellFederationCounterpartyIncidentStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationCounterpartyIncidentFilter{}, err
	}
	return securecellsintegration.SecureCellFederationCounterpartyIncidentFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		ContractID:     strings.TrimSpace(query.Get("contract_id")),
		Status:         status,
		Signer:         strings.TrimSpace(query.Get("signer")),
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationCounterpartyIncidentReportFilter(r *http.Request) (securecellsintegration.SecureCellFederationCounterpartyIncidentReportFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	status, err := parseSecureCellFederationCounterpartyIncidentReportStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportFilter{}, err
	}
	reconciliationStatus, err := parseSecureCellFederationIncidentReportReconciliationStatus(query.Get("reconciliation_status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportFilter{}, err
	}
	return securecellsintegration.SecureCellFederationCounterpartyIncidentReportFilter{
		CellID:               strings.TrimSpace(query.Get("cell_id")),
		OrganizationID:       strings.TrimSpace(query.Get("organization_id")),
		ContractID:           strings.TrimSpace(query.Get("contract_id")),
		IncidentID:           strings.TrimSpace(query.Get("incident_id")),
		ResponseID:           strings.TrimSpace(query.Get("response_id")),
		ReportID:             strings.TrimSpace(query.Get("report_id")),
		Status:               status,
		ReconciliationStatus: reconciliationStatus,
		Signer:               strings.TrimSpace(query.Get("signer")),
		Regulator:            strings.TrimSpace(query.Get("regulator")),
		Limit:                cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationCounterpartyIncidentReportAmendmentFilter(r *http.Request) (securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	status, err := parseSecureCellFederationCounterpartyIncidentReportAmendmentStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentFilter{}, err
	}
	reconciliationStatus, err := parseSecureCellFederationIncidentReportAmendmentReconciliationStatus(query.Get("reconciliation_status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentFilter{}, err
	}
	return securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentFilter{
		CellID:               strings.TrimSpace(query.Get("cell_id")),
		OrganizationID:       strings.TrimSpace(query.Get("organization_id")),
		ContractID:           strings.TrimSpace(query.Get("contract_id")),
		IncidentID:           strings.TrimSpace(query.Get("incident_id")),
		ResponseID:           strings.TrimSpace(query.Get("response_id")),
		ReportID:             strings.TrimSpace(query.Get("report_id")),
		AmendmentID:          strings.TrimSpace(query.Get("amendment_id")),
		Status:               status,
		ReconciliationStatus: reconciliationStatus,
		Signer:               strings.TrimSpace(query.Get("signer")),
		Regulator:            strings.TrimSpace(query.Get("regulator")),
		Limit:                cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentReportReconciliationFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentReportReconciliationFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	reportingParty, err := parseSecureCellFederationIncidentResponseParty(query.Get("reporting_party"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationFilter{}, err
	}
	status, err := parseSecureCellFederationIncidentReportReconciliationStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentReportReconciliationFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ComparisonKey:  strings.TrimSpace(query.Get("comparison_key")),
		Regulator:      strings.TrimSpace(query.Get("regulator")),
		ReportingParty: reportingParty,
		Status:         status,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentReportAmendmentReconciliationFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	reportingParty, err := parseSecureCellFederationIncidentResponseParty(query.Get("reporting_party"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationFilter{}, err
	}
	status, err := parseSecureCellFederationIncidentReportAmendmentReconciliationStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ComparisonKey:  strings.TrimSpace(query.Get("comparison_key")),
		Regulator:      strings.TrimSpace(query.Get("regulator")),
		ReportingParty: reportingParty,
		Status:         status,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentReportReconciliationActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentReportReconciliationActionFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationActionFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	action, err := parseSecureCellFederationIncidentReportReconciliationActionType(query.Get("action"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationActionFilter{}, err
	}
	reviewStatus, err := parseSecureCellFederationIncidentReportReviewStatus(query.Get("review_status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationActionFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentReportReconciliationActionFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ComparisonKey:  strings.TrimSpace(query.Get("comparison_key")),
		Action:         action,
		ReviewStatus:   reviewStatus,
		ActorDID:       strings.TrimSpace(query.Get("actor_did")),
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentReportAmendmentReconciliationActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	action, err := parseSecureCellFederationIncidentReportAmendmentReconciliationActionType(query.Get("action"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionFilter{}, err
	}
	reviewStatus, err := parseSecureCellFederationIncidentReportReviewStatus(query.Get("review_status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ComparisonKey:  strings.TrimSpace(query.Get("comparison_key")),
		Action:         action,
		ReviewStatus:   reviewStatus,
		ActorDID:       strings.TrimSpace(query.Get("actor_did")),
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	attestation, err := parseSecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType(query.Get("attestation"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter{}, err
	}
	attestationStatus, err := parseSecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus(query.Get("attestation_status"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter{
		CellID:            strings.TrimSpace(query.Get("cell_id")),
		OrganizationID:    strings.TrimSpace(query.Get("organization_id")),
		IncidentID:        strings.TrimSpace(query.Get("incident_id")),
		ComparisonKey:     strings.TrimSpace(query.Get("comparison_key")),
		Attestation:       attestation,
		AttestationStatus: attestationStatus,
		ActorDID:          strings.TrimSpace(query.Get("actor_did")),
		Limit:             cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter(r *http.Request) (securecellsintegration.SecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	before, err := parseSecureCellOptionalTime(query.Get("before"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter{}, err
	}
	status, err := parseSecureCellFederationIncidentReportAmendmentReconciliationStatus(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter{}, err
	}
	reviewStatus, err := parseSecureCellFederationIncidentReportReviewStatus(query.Get("review_status"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter{}, err
	}
	attestationStatus, err := parseSecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus(query.Get("attestation_status"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter{}, err
	}
	return securecellsintegration.SecureCellOverdueFederationIncidentReportAmendmentReconciliationFilter{
		CellID:            strings.TrimSpace(query.Get("cell_id")),
		OrganizationID:    strings.TrimSpace(query.Get("organization_id")),
		IncidentID:        strings.TrimSpace(query.Get("incident_id")),
		ComparisonKey:     strings.TrimSpace(query.Get("comparison_key")),
		Status:            status,
		ReviewStatus:      reviewStatus,
		AttestationStatus: attestationStatus,
		Before:            before,
		Limit:             cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentReportAmendmentReconciliationAutomationActionFilter(r *http.Request) (securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionFilter{}, err
	}
	return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionFilter{
		CellID:         strings.TrimSpace(query.Get("cell_id")),
		OrganizationID: strings.TrimSpace(query.Get("organization_id")),
		IncidentID:     strings.TrimSpace(query.Get("incident_id")),
		ComparisonKey:  strings.TrimSpace(query.Get("comparison_key")),
		ContractID:     strings.TrimSpace(query.Get("contract_id")),
		Action:         strings.TrimSpace(query.Get("action")),
		Since:          since,
		Until:          until,
		Limit:          cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellFederationIncidentResponseStatus(raw string) (securecellsintegration.SecureCellFederationIncidentResponseStatus, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentResponseStatusPendingLocalAck):
		return securecellsintegration.SecureCellFederationIncidentResponseStatusPendingLocalAck, nil
	case string(securecellsintegration.SecureCellFederationIncidentResponseStatusPendingCounterpartyAck):
		return securecellsintegration.SecureCellFederationIncidentResponseStatusPendingCounterpartyAck, nil
	case string(securecellsintegration.SecureCellFederationIncidentResponseStatusAcknowledged):
		return securecellsintegration.SecureCellFederationIncidentResponseStatusAcknowledged, nil
	case string(securecellsintegration.SecureCellFederationIncidentResponseStatusEscalated):
		return securecellsintegration.SecureCellFederationIncidentResponseStatusEscalated, nil
	case string(securecellsintegration.SecureCellFederationIncidentResponseStatusRemediating):
		return securecellsintegration.SecureCellFederationIncidentResponseStatusRemediating, nil
	case string(securecellsintegration.SecureCellFederationIncidentResponseStatusRemediated):
		return securecellsintegration.SecureCellFederationIncidentResponseStatusRemediated, nil
	case string(securecellsintegration.SecureCellFederationIncidentResponseStatusClosed):
		return securecellsintegration.SecureCellFederationIncidentResponseStatusClosed, nil
	default:
		return "", fmt.Errorf("unsupported federation incident response status %q", raw)
	}
}

func parseSecureCellFederationIncidentResponseSource(raw string) (securecellsintegration.SecureCellFederationIncidentResponseSource, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentResponseSourceLocalIncident):
		return securecellsintegration.SecureCellFederationIncidentResponseSourceLocalIncident, nil
	case string(securecellsintegration.SecureCellFederationIncidentResponseSourceCounterpartyIncident):
		return securecellsintegration.SecureCellFederationIncidentResponseSourceCounterpartyIncident, nil
	default:
		return "", fmt.Errorf("unsupported federation incident response source %q", raw)
	}
}

func parseSecureCellFederationIncidentResponseParty(raw string) (securecellsintegration.SecureCellFederationIncidentResponseParty, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentResponsePartyLocalOrg):
		return securecellsintegration.SecureCellFederationIncidentResponsePartyLocalOrg, nil
	case string(securecellsintegration.SecureCellFederationIncidentResponsePartyCounterpartyOrg):
		return securecellsintegration.SecureCellFederationIncidentResponsePartyCounterpartyOrg, nil
	default:
		return "", fmt.Errorf("unsupported federation incident response party %q", raw)
	}
}

func parseSecureCellFederationIncidentReportStatus(raw string) (securecellsintegration.SecureCellFederationIncidentReportStatus, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentReportStatusPendingSubmission):
		return securecellsintegration.SecureCellFederationIncidentReportStatusPendingSubmission, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportStatusSubmitted):
		return securecellsintegration.SecureCellFederationIncidentReportStatusSubmitted, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportStatusAcknowledged):
		return securecellsintegration.SecureCellFederationIncidentReportStatusAcknowledged, nil
	default:
		return "", fmt.Errorf("unsupported federation incident report status %q", raw)
	}
}

func parseSecureCellFederationIncidentRemediationVerificationDecision(raw string) (securecellsintegration.SecureCellFederationIncidentRemediationVerificationDecision, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentRemediationVerificationDecisionAccepted):
		return securecellsintegration.SecureCellFederationIncidentRemediationVerificationDecisionAccepted, nil
	case string(securecellsintegration.SecureCellFederationIncidentRemediationVerificationDecisionRejected):
		return securecellsintegration.SecureCellFederationIncidentRemediationVerificationDecisionRejected, nil
	default:
		return "", fmt.Errorf("unsupported federation incident remediation verification decision %q", raw)
	}
}

func parseSecureCellFederationAssuranceSeverity(raw string) (securecellsintegration.SecureCellFederationAssuranceSeverity, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationAssuranceSeverityInfo):
		return securecellsintegration.SecureCellFederationAssuranceSeverityInfo, nil
	case string(securecellsintegration.SecureCellFederationAssuranceSeverityWarning):
		return securecellsintegration.SecureCellFederationAssuranceSeverityWarning, nil
	case string(securecellsintegration.SecureCellFederationAssuranceSeverityCritical):
		return securecellsintegration.SecureCellFederationAssuranceSeverityCritical, nil
	default:
		return "", fmt.Errorf("unsupported federation assurance severity %q", raw)
	}
}

func parseSecureCellFederationAssuranceCategory(raw string) (securecellsintegration.SecureCellFederationAssuranceCategory, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryContractCoverage):
		return securecellsintegration.SecureCellFederationAssuranceCategoryContractCoverage, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryParticipantContinuity):
		return securecellsintegration.SecureCellFederationAssuranceCategoryParticipantContinuity, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryExpectedIdentityDrift):
		return securecellsintegration.SecureCellFederationAssuranceCategoryExpectedIdentityDrift, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryCredentialContinuity):
		return securecellsintegration.SecureCellFederationAssuranceCategoryCredentialContinuity, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategorySessionScopeDrift):
		return securecellsintegration.SecureCellFederationAssuranceCategorySessionScopeDrift, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryPolicyDrift):
		return securecellsintegration.SecureCellFederationAssuranceCategoryPolicyDrift, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryConfidentialComputeDrift):
		return securecellsintegration.SecureCellFederationAssuranceCategoryConfidentialComputeDrift, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryArtifactExposure):
		return securecellsintegration.SecureCellFederationAssuranceCategoryArtifactExposure, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryConcurrentRevision):
		return securecellsintegration.SecureCellFederationAssuranceCategoryConcurrentRevision, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyAssuranceMissing):
		return securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyAssuranceMissing, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyAssuranceInvalid):
		return securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyAssuranceInvalid, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyAssuranceExpired):
		return securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyAssuranceExpired, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyAssuranceStale):
		return securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyAssuranceStale, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyAssuranceCritical):
		return securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyAssuranceCritical, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyScopeDrift):
		return securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyScopeDrift, nil
	case string(securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyConfidentialDrift):
		return securecellsintegration.SecureCellFederationAssuranceCategoryCounterpartyConfidentialDrift, nil
	default:
		return "", fmt.Errorf("unsupported federation assurance category %q", raw)
	}
}

func parseSecureCellFederationCounterpartyAssuranceStatus(raw string) (securecellsintegration.SecureCellFederationCounterpartyAssuranceStatus, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationCounterpartyAssuranceStatusVerified):
		return securecellsintegration.SecureCellFederationCounterpartyAssuranceStatusVerified, nil
	case string(securecellsintegration.SecureCellFederationCounterpartyAssuranceStatusStale):
		return securecellsintegration.SecureCellFederationCounterpartyAssuranceStatusStale, nil
	case string(securecellsintegration.SecureCellFederationCounterpartyAssuranceStatusExpired):
		return securecellsintegration.SecureCellFederationCounterpartyAssuranceStatusExpired, nil
	case string(securecellsintegration.SecureCellFederationCounterpartyAssuranceStatusInvalid):
		return securecellsintegration.SecureCellFederationCounterpartyAssuranceStatusInvalid, nil
	default:
		return "", fmt.Errorf("unsupported federation counterparty assurance status %q", raw)
	}
}

func parseSecureCellFederationIncidentStatus(raw string) (securecellsintegration.SecureCellFederationIncidentStatus, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentStatusOpen):
		return securecellsintegration.SecureCellFederationIncidentStatusOpen, nil
	case string(securecellsintegration.SecureCellFederationIncidentStatusResolved):
		return securecellsintegration.SecureCellFederationIncidentStatusResolved, nil
	default:
		return "", fmt.Errorf("unsupported federation incident status %q", raw)
	}
}

func parseSecureCellFederationIncidentSeverity(raw string) (securecellsintegration.SecureCellFederationIncidentSeverity, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentSeverityInfo):
		return securecellsintegration.SecureCellFederationIncidentSeverityInfo, nil
	case string(securecellsintegration.SecureCellFederationIncidentSeverityWarning):
		return securecellsintegration.SecureCellFederationIncidentSeverityWarning, nil
	case string(securecellsintegration.SecureCellFederationIncidentSeverityHigh):
		return securecellsintegration.SecureCellFederationIncidentSeverityHigh, nil
	case string(securecellsintegration.SecureCellFederationIncidentSeverityCritical):
		return securecellsintegration.SecureCellFederationIncidentSeverityCritical, nil
	default:
		return "", fmt.Errorf("unsupported federation incident severity %q", raw)
	}
}

func parseSecureCellFederationIncidentCategory(raw string) (securecellsintegration.SecureCellFederationIncidentCategory, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentCategoryIdentityCompromise):
		return securecellsintegration.SecureCellFederationIncidentCategoryIdentityCompromise, nil
	case string(securecellsintegration.SecureCellFederationIncidentCategoryCredentialCompromise):
		return securecellsintegration.SecureCellFederationIncidentCategoryCredentialCompromise, nil
	case string(securecellsintegration.SecureCellFederationIncidentCategoryConfidentialComputeFailure):
		return securecellsintegration.SecureCellFederationIncidentCategoryConfidentialComputeFailure, nil
	case string(securecellsintegration.SecureCellFederationIncidentCategoryDataExposure):
		return securecellsintegration.SecureCellFederationIncidentCategoryDataExposure, nil
	case string(securecellsintegration.SecureCellFederationIncidentCategoryUnauthorizedExchange):
		return securecellsintegration.SecureCellFederationIncidentCategoryUnauthorizedExchange, nil
	case string(securecellsintegration.SecureCellFederationIncidentCategoryPolicyBreach):
		return securecellsintegration.SecureCellFederationIncidentCategoryPolicyBreach, nil
	case string(securecellsintegration.SecureCellFederationIncidentCategoryMalwareOrTamper):
		return securecellsintegration.SecureCellFederationIncidentCategoryMalwareOrTamper, nil
	case string(securecellsintegration.SecureCellFederationIncidentCategoryCounterpartyOutage):
		return securecellsintegration.SecureCellFederationIncidentCategoryCounterpartyOutage, nil
	default:
		return "", fmt.Errorf("unsupported federation incident category %q", raw)
	}
}

func parseSecureCellFederationCounterpartyIncidentStatus(raw string) (securecellsintegration.SecureCellFederationCounterpartyIncidentStatus, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationCounterpartyIncidentStatusVerified):
		return securecellsintegration.SecureCellFederationCounterpartyIncidentStatusVerified, nil
	case string(securecellsintegration.SecureCellFederationCounterpartyIncidentStatusStale):
		return securecellsintegration.SecureCellFederationCounterpartyIncidentStatusStale, nil
	case string(securecellsintegration.SecureCellFederationCounterpartyIncidentStatusExpired):
		return securecellsintegration.SecureCellFederationCounterpartyIncidentStatusExpired, nil
	case string(securecellsintegration.SecureCellFederationCounterpartyIncidentStatusInvalid):
		return securecellsintegration.SecureCellFederationCounterpartyIncidentStatusInvalid, nil
	default:
		return "", fmt.Errorf("unsupported federation counterparty incident status %q", raw)
	}
}

func parseSecureCellFederationCounterpartyIncidentReportStatus(raw string) (securecellsintegration.SecureCellFederationCounterpartyIncidentReportStatus, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationCounterpartyIncidentReportStatusVerified):
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportStatusVerified, nil
	case string(securecellsintegration.SecureCellFederationCounterpartyIncidentReportStatusStale):
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportStatusStale, nil
	case string(securecellsintegration.SecureCellFederationCounterpartyIncidentReportStatusExpired):
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportStatusExpired, nil
	case string(securecellsintegration.SecureCellFederationCounterpartyIncidentReportStatusInvalid):
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportStatusInvalid, nil
	default:
		return "", fmt.Errorf("unsupported federation counterparty incident report status %q", raw)
	}
}

func parseSecureCellFederationCounterpartyIncidentReportAmendmentStatus(raw string) (securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentStatus, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentStatusVerified):
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentStatusVerified, nil
	case string(securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentStatusStale):
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentStatusStale, nil
	case string(securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentStatusExpired):
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentStatusExpired, nil
	case string(securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentStatusInvalid):
		return securecellsintegration.SecureCellFederationCounterpartyIncidentReportAmendmentStatusInvalid, nil
	default:
		return "", fmt.Errorf("unsupported federation counterparty incident report amendment status %q", raw)
	}
}

func parseSecureCellFederationIncidentReportReconciliationStatus(raw string) (securecellsintegration.SecureCellFederationIncidentReportReconciliationStatus, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusAligned):
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusAligned, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusLocalOnly):
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusLocalOnly, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusCounterpartyOnly):
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusCounterpartyOnly, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusDivergent):
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusDivergent, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusCounterpartyInvalid):
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusCounterpartyInvalid, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusCounterpartyStale):
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusCounterpartyStale, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusCounterpartyExpired):
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationStatusCounterpartyExpired, nil
	default:
		return "", fmt.Errorf("unsupported federation incident report reconciliation status %q", raw)
	}
}

func parseSecureCellFederationIncidentReportAmendmentReconciliationStatus(raw string) (securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatus, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusAligned):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusAligned, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusLocalOnly):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusLocalOnly, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyOnly):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyOnly, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusDivergent):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusDivergent, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyInvalid):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyInvalid, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyStale):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyStale, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyExpired):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationStatusCounterpartyExpired, nil
	default:
		return "", fmt.Errorf("unsupported federation incident report amendment reconciliation status %q", raw)
	}
}

func parseSecureCellFederationIncidentReportReconciliationActionType(raw string) (securecellsintegration.SecureCellFederationIncidentReportReconciliationActionType, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReconciliationActionAcknowledge):
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationActionAcknowledge, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReconciliationActionDispute):
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationActionDispute, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReconciliationActionResolve):
		return securecellsintegration.SecureCellFederationIncidentReportReconciliationActionResolve, nil
	default:
		return "", fmt.Errorf("unsupported federation incident report reconciliation action %q", raw)
	}
}

func parseSecureCellFederationIncidentReportAmendmentReconciliationActionType(raw string) (securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionType, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionAcknowledge):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionAcknowledge, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionDispute):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionDispute, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionResolve):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationActionResolve, nil
	default:
		return "", fmt.Errorf("unsupported federation incident report amendment reconciliation action %q", raw)
	}
}

func parseSecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType(raw string) (securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationType, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationAcknowledge):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationAcknowledge, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationCorrect):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationCorrect, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationResolve):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationResolve, nil
	default:
		return "", fmt.Errorf("unsupported federation incident report amendment reconciliation counterparty attestation %q", raw)
	}
}

func parseSecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus(raw string) (securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatus, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusUnattested, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusAcknowledged):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusAcknowledged, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusCorrected):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusCorrected, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusResolved):
		return securecellsintegration.SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationStatusResolved, nil
	default:
		return "", fmt.Errorf("unsupported federation incident report amendment reconciliation counterparty attestation status %q", raw)
	}
}

func parseSecureCellFederationIncidentReportReviewStatus(raw string) (securecellsintegration.SecureCellFederationIncidentReportReviewStatus, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReviewStatusUnreviewed):
		return securecellsintegration.SecureCellFederationIncidentReportReviewStatusUnreviewed, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReviewStatusAcknowledged):
		return securecellsintegration.SecureCellFederationIncidentReportReviewStatusAcknowledged, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReviewStatusDisputed):
		return securecellsintegration.SecureCellFederationIncidentReportReviewStatusDisputed, nil
	case string(securecellsintegration.SecureCellFederationIncidentReportReviewStatusResolved):
		return securecellsintegration.SecureCellFederationIncidentReportReviewStatusResolved, nil
	default:
		return "", fmt.Errorf("unsupported federation incident report review status %q", raw)
	}
}

func parseSecureCellOverdueDecisionFilter(r *http.Request) (securecellsintegration.SecureCellOverdueDecisionFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellOverdueDecisionFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	statuses, err := parseSecureCellDecisionStatuses(query.Get("status"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueDecisionFilter{}, err
	}
	before, err := parseSecureCellOptionalTime(query.Get("before"))
	if err != nil {
		return securecellsintegration.SecureCellOverdueDecisionFilter{}, err
	}
	return securecellsintegration.SecureCellOverdueDecisionFilter{
		CellID:           strings.TrimSpace(query.Get("cell_id")),
		Jurisdiction:     strings.TrimSpace(query.Get("jurisdiction")),
		ParticipantDID:   strings.TrimSpace(query.Get("participant_did")),
		SLATemplate:      strings.TrimSpace(query.Get("sla_template")),
		SectorPolicyPack: strings.TrimSpace(query.Get("sector_policy_pack")),
		Statuses:         statuses,
		Before:           before,
		Limit:            cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellDecisionAutomationActionFilter(r *http.Request) (securecellsintegration.SecureCellDecisionAutomationActionFilter, error) {
	if r == nil {
		return securecellsintegration.SecureCellDecisionAutomationActionFilter{}, fmt.Errorf("request is required")
	}
	query := r.URL.Query()
	since, err := parseSecureCellOptionalTime(query.Get("since"))
	if err != nil {
		return securecellsintegration.SecureCellDecisionAutomationActionFilter{}, err
	}
	until, err := parseSecureCellOptionalTime(query.Get("until"))
	if err != nil {
		return securecellsintegration.SecureCellDecisionAutomationActionFilter{}, err
	}
	return securecellsintegration.SecureCellDecisionAutomationActionFilter{
		CellID:           strings.TrimSpace(query.Get("cell_id")),
		SessionID:        strings.TrimSpace(query.Get("session_id")),
		ThreadID:         strings.TrimSpace(query.Get("thread_id")),
		DecisionID:       strings.TrimSpace(query.Get("decision_id")),
		SLATemplate:      strings.TrimSpace(query.Get("sla_template")),
		SectorPolicyPack: strings.TrimSpace(query.Get("sector_policy_pack")),
		Action:           strings.TrimSpace(query.Get("action")),
		Since:            since,
		Until:            until,
		Limit:            cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}, nil
}

func parseSecureCellDecisionSLATemplateFilter(r *http.Request) securecellsintegration.SecureCellDecisionSLATemplateFilter {
	if r == nil {
		return securecellsintegration.SecureCellDecisionSLATemplateFilter{}
	}
	query := r.URL.Query()
	return securecellsintegration.SecureCellDecisionSLATemplateFilter{
		Sector:             strings.TrimSpace(query.Get("sector")),
		SectorPolicyPack:   strings.TrimSpace(query.Get("sector_policy_pack")),
		GovernanceTemplate: strings.TrimSpace(query.Get("governance_template")),
		Limit:              cast.ToInt(strings.TrimSpace(query.Get("limit"))),
	}
}

func parseSecureCellFederationOrganizationStatus(raw string) (securecellsintegration.SecureCellFederationOrganizationStatus, error) {
	switch status := securecellsintegration.SecureCellFederationOrganizationStatus(strings.ToLower(strings.TrimSpace(raw))); status {
	case "":
		return "", nil
	case securecellsintegration.SecureCellFederationOrganizationStatusPending,
		securecellsintegration.SecureCellFederationOrganizationStatusActive,
		securecellsintegration.SecureCellFederationOrganizationStatusRevoked:
		return status, nil
	default:
		return "", fmt.Errorf("unsupported federation organization status %q", raw)
	}
}

func parseSecureCellFederationInvitationStatus(raw string) (securecellsintegration.SecureCellFederationInvitationStatus, error) {
	switch status := securecellsintegration.SecureCellFederationInvitationStatus(strings.ToLower(strings.TrimSpace(raw))); status {
	case "":
		return "", nil
	case securecellsintegration.SecureCellFederationInvitationStatusPending,
		securecellsintegration.SecureCellFederationInvitationStatusAccepted,
		securecellsintegration.SecureCellFederationInvitationStatusRevoked:
		return status, nil
	default:
		return "", fmt.Errorf("unsupported federation invitation status %q", raw)
	}
}

func parseSecureCellFederationContractStatus(raw string) (securecellsintegration.SecureCellFederationContractStatus, error) {
	switch status := securecellsintegration.SecureCellFederationContractStatus(strings.ToLower(strings.TrimSpace(raw))); status {
	case "":
		return "", nil
	case securecellsintegration.SecureCellFederationContractStatusActive,
		securecellsintegration.SecureCellFederationContractStatusSuspended,
		securecellsintegration.SecureCellFederationContractStatusRevoked:
		return status, nil
	default:
		return "", fmt.Errorf("unsupported federation contract status %q", raw)
	}
}

func parseSecureCellFederationCounterproposalStatus(raw string) (securecellsintegration.SecureCellFederationCounterproposalStatus, error) {
	switch status := securecellsintegration.SecureCellFederationCounterproposalStatus(strings.ToLower(strings.TrimSpace(raw))); status {
	case "":
		return "", nil
	case securecellsintegration.SecureCellFederationCounterproposalStatusPending,
		securecellsintegration.SecureCellFederationCounterproposalStatusApproved,
		securecellsintegration.SecureCellFederationCounterproposalStatusRejected,
		securecellsintegration.SecureCellFederationCounterproposalStatusSuperseded:
		return status, nil
	default:
		return "", fmt.Errorf("unsupported federation counterproposal status %q", raw)
	}
}

func parseSecureCellStatuses(raw string) ([]securecellsintegration.SecureCellStatus, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	statuses := make([]securecellsintegration.SecureCellStatus, 0, len(parts))
	for _, part := range parts {
		status, err := parseSecureCellStatus(part)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func parseSecureCellDecisionStatuses(raw string) ([]securecellsintegration.SecureCellThreadDecisionStatus, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	statuses := make([]securecellsintegration.SecureCellThreadDecisionStatus, 0, len(parts))
	for _, part := range parts {
		status, err := parseSecureCellDecisionStatus(part)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func parseSecureCellDecisionStatus(raw string) (securecellsintegration.SecureCellThreadDecisionStatus, error) {
	switch securecellsintegration.SecureCellThreadDecisionStatus(strings.ToLower(strings.TrimSpace(raw))) {
	case securecellsintegration.SecureCellThreadDecisionStatusOpen,
		securecellsintegration.SecureCellThreadDecisionStatusApproved,
		securecellsintegration.SecureCellThreadDecisionStatusQuorumFailed,
		securecellsintegration.SecureCellThreadDecisionStatusQuarantined,
		securecellsintegration.SecureCellThreadDecisionStatusClosed:
		return securecellsintegration.SecureCellThreadDecisionStatus(strings.ToLower(strings.TrimSpace(raw))), nil
	default:
		return "", fmt.Errorf("invalid secure cell decision status %q", raw)
	}
}

func parseSecureCellStatus(raw string) (securecellsintegration.SecureCellStatus, error) {
	switch securecellsintegration.SecureCellStatus(strings.ToLower(strings.TrimSpace(raw))) {
	case securecellsintegration.SecureCellStatusActive,
		securecellsintegration.SecureCellStatusPaused,
		securecellsintegration.SecureCellStatusQuarantined,
		securecellsintegration.SecureCellStatusRevoked,
		securecellsintegration.SecureCellStatusTerminated,
		securecellsintegration.SecureCellStatusRejected:
		return securecellsintegration.SecureCellStatus(strings.ToLower(strings.TrimSpace(raw))), nil
	default:
		return "", fmt.Errorf("invalid secure cell status %q", raw)
	}
}

func parseSecureCellOptionalTime(raw string) (*time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var parsed time.Time
	var err error
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		parsed, err = time.Parse(layout, raw)
		if err == nil {
			parsed = parsed.UTC()
			return &parsed, nil
		}
	}
	return nil, fmt.Errorf("invalid timestamp %q: %w", raw, err)
}

func resolveSecureCellControlLedgerDir(appOpts servertypes.AppOptions) string {
	configuredDir := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.control_ledger_dir")),
		cast.ToString(appOpts.Get("secure_cells.control_ledger_dir")),
		os.Getenv("AETHELRED_SECURE_CELLS_CONTROL_LEDGER_DIR"),
	)
	if configuredDir != "" {
		return filepath.Clean(configuredDir)
	}

	homePath := cast.ToString(appOpts.Get(flags.FlagHome))
	if homePath == "" {
		homePath = DefaultNodeHome
	}
	if homePath == "" {
		return filepath.Clean(filepath.Join(".", "data", "secure-cells", "control-ledgers"))
	}
	return filepath.Join(homePath, "data", "secure-cells", "control-ledgers")
}

func resolveSecureCellWorkflowStoreDir(appOpts servertypes.AppOptions) string {
	configuredDir := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.workflow_store_dir")),
		cast.ToString(appOpts.Get("secure_cells.workflow_store_dir")),
		os.Getenv("AETHELRED_SECURE_CELLS_WORKFLOW_STORE_DIR"),
	)
	if configuredDir != "" {
		return filepath.Clean(configuredDir)
	}

	homePath := cast.ToString(appOpts.Get(flags.FlagHome))
	if homePath == "" {
		homePath = DefaultNodeHome
	}
	if homePath == "" {
		return filepath.Clean(filepath.Join(".", "data", "secure-cells", "workflows"))
	}
	return filepath.Join(homePath, "data", "secure-cells", "workflows")
}

func resolveSecureCellPolicySigner(appOpts servertypes.AppOptions) (*ecdsa.PrivateKey, string, string, string, error) {
	signer := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.policy_signer")),
		cast.ToString(appOpts.Get("secure_cells.policy_signer")),
		os.Getenv("AETHELRED_SECURE_CELLS_POLICY_SIGNER"),
	)
	if strings.TrimSpace(signer) == "" {
		signer = "did:aethelred:policy-gateway-secure-cells"
	}

	keyHex := strings.TrimSpace(firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.secure_cells.policy_signer_key")),
		cast.ToString(appOpts.Get("secure_cells.policy_signer_key")),
		os.Getenv("AETHELRED_SECURE_CELLS_POLICY_SIGNER_KEY"),
	))
	if keyHex == "" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, "", "", "", err
		}
		return key, signer, "ephemeral", "generated an ephemeral secure-cell policy signer because no configured signer key was provided", nil
	}

	key, err := parseFinanceECDSAPrivateKeyHex(keyHex)
	if err != nil {
		return nil, "", "", "", err
	}
	return key, signer, "configured", "loaded secure-cell policy signer from configuration", nil
}

func parseSecureCellID(path, suffix string) (string, error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", fmt.Errorf("invalid secure cell path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", fmt.Errorf("invalid secure cell action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	remainder = strings.Trim(remainder, "/")
	if remainder == "" || strings.Contains(remainder, "/") {
		return "", fmt.Errorf("invalid secure cell ID")
	}
	return remainder, nil
}

func parseSecureCellMemberActionPath(path string) (cellID string, participantDID string, action string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", fmt.Errorf("invalid secure cell member mutation path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "members" {
		return "", "", "", fmt.Errorf("invalid secure cell member mutation path")
	}
	cellID = strings.TrimSpace(parts[0])
	participantDID = strings.TrimSpace(parts[2])
	action = strings.TrimSpace(parts[3])
	if cellID == "" || participantDID == "" || action == "" {
		return "", "", "", fmt.Errorf("invalid secure cell member mutation path")
	}
	return cellID, participantDID, action, nil
}

func parseSecureCellBulkMemberActionPath(path string) (cellID string, action string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell bulk mutation path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "members" || parts[2] != "bulk" {
		return "", "", fmt.Errorf("invalid secure cell bulk mutation path")
	}
	cellID = strings.TrimSpace(parts[0])
	action = strings.TrimSpace(parts[3])
	if cellID == "" || action == "" {
		return "", "", fmt.Errorf("invalid secure cell bulk mutation path")
	}
	return cellID, action, nil
}

func parseSecureCellLifecycleActionPath(path string) (cellID string, action string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell lifecycle path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid secure cell lifecycle path")
	}
	cellID = strings.TrimSpace(parts[0])
	action = strings.TrimSpace(parts[1])
	if cellID == "" || action == "" {
		return "", "", fmt.Errorf("invalid secure cell lifecycle path")
	}
	return cellID, action, nil
}

func parseSecureCellFederationInvitationActionPath(path string, suffix string) (cellID string, invitationID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation invitation path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation invitation action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "invitations" {
		return "", "", fmt.Errorf("invalid secure cell federation invitation action path")
	}
	cellID = strings.TrimSpace(parts[0])
	invitationID = strings.TrimSpace(parts[3])
	if cellID == "" || invitationID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation invitation action path")
	}
	return cellID, invitationID, nil
}

func parseSecureCellFederationOrganizationActionPath(path string, suffix string) (cellID string, organizationID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation organization path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation organization action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "organizations" {
		return "", "", fmt.Errorf("invalid secure cell federation organization action path")
	}
	cellID = strings.TrimSpace(parts[0])
	organizationID = strings.TrimSpace(parts[3])
	if cellID == "" || organizationID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation organization action path")
	}
	return cellID, organizationID, nil
}

func parseSecureCellFederationIncidentActionPath(path string, suffix string) (cellID string, organizationID string, incidentID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", fmt.Errorf("invalid secure cell federation incident path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", "", fmt.Errorf("invalid secure cell federation incident action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 6 || parts[1] != "federation" || parts[2] != "organizations" || parts[4] != "incidents" {
		return "", "", "", fmt.Errorf("invalid secure cell federation incident action path")
	}
	cellID = strings.TrimSpace(parts[0])
	organizationID = strings.TrimSpace(parts[3])
	incidentID = strings.TrimSpace(parts[5])
	if cellID == "" || organizationID == "" || incidentID == "" {
		return "", "", "", fmt.Errorf("invalid secure cell federation incident action path")
	}
	return cellID, organizationID, incidentID, nil
}

func parseSecureCellFederationIncidentResponseActionPath(path string, suffix string) (cellID string, responseID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation incident response path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation incident response action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-responses" {
		return "", "", fmt.Errorf("invalid secure cell federation incident response action path")
	}
	cellID = strings.TrimSpace(parts[0])
	responseID = strings.TrimSpace(parts[3])
	if cellID == "" || responseID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation incident response action path")
	}
	return cellID, responseID, nil
}

func parseSecureCellFederationIncidentReportActionPath(path string, suffix string) (cellID string, reportID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation incident report path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation incident report action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-reports" {
		return "", "", fmt.Errorf("invalid secure cell federation incident report action path")
	}
	cellID = strings.TrimSpace(parts[0])
	reportID = strings.TrimSpace(parts[3])
	if cellID == "" || reportID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation incident report action path")
	}
	return cellID, reportID, nil
}

func parseSecureCellFederationIncidentReportAmendmentActionPath(path string, suffix string) (cellID string, amendmentID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation incident report amendment path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation incident report amendment action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-report-amendments" {
		return "", "", fmt.Errorf("invalid secure cell federation incident report amendment action path")
	}
	cellID = strings.TrimSpace(parts[0])
	amendmentID = strings.TrimSpace(parts[3])
	if cellID == "" || amendmentID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation incident report amendment action path")
	}
	return cellID, amendmentID, nil
}

func parseSecureCellFederationIncidentReportReconciliationActionPath(path string, suffix string) (cellID string, comparisonKey string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation incident report reconciliation path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation incident report reconciliation action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-report-reconciliations" {
		return "", "", fmt.Errorf("invalid secure cell federation incident report reconciliation action path")
	}
	cellID = strings.TrimSpace(parts[0])
	comparisonKey, err = url.PathUnescape(strings.TrimSpace(parts[3]))
	if err != nil {
		return "", "", fmt.Errorf("invalid secure cell federation incident report reconciliation key: %w", err)
	}
	if cellID == "" || strings.TrimSpace(comparisonKey) == "" {
		return "", "", fmt.Errorf("invalid secure cell federation incident report reconciliation action path")
	}
	return cellID, strings.TrimSpace(comparisonKey), nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionPath(path string, suffix string) (cellID string, comparisonKey string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-directive-extension-appeal-reconciliations" {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation action path")
	}
	cellID = strings.TrimSpace(parts[0])
	comparisonKey, err = url.PathUnescape(strings.TrimSpace(parts[3]))
	if err != nil {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation key: %w", err)
	}
	if cellID == "" || strings.TrimSpace(comparisonKey) == "" {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation action path")
	}
	return cellID, strings.TrimSpace(comparisonKey), nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionPath(path string, suffix string) (cellID string, challengeAppealID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-directive-extension-appeal-reconciliation-challenge-appeals" {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal action path")
	}
	cellID = strings.TrimSpace(parts[0])
	challengeAppealID = strings.TrimSpace(parts[3])
	if cellID == "" || challengeAppealID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal action path")
	}
	return cellID, challengeAppealID, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionPath(path string, suffix string) (cellID string, challengeAppealID string, responseAppealID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 6 || parts[1] != "federation" || parts[2] != "incident-directive-extension-appeal-reconciliation-challenge-appeals" || parts[4] != "alignment-response-appeals" {
		return "", "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal action path")
	}
	cellID = strings.TrimSpace(parts[0])
	challengeAppealID = strings.TrimSpace(parts[3])
	responseAppealID = strings.TrimSpace(parts[5])
	if cellID == "" || challengeAppealID == "" || responseAppealID == "" {
		return "", "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal action path")
	}
	return cellID, challengeAppealID, responseAppealID, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewPath(path string, suffix string) (cellID string, reviewID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-reviews" {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review action path")
	}
	cellID = strings.TrimSpace(parts[0])
	reviewID = strings.TrimSpace(parts[3])
	if cellID == "" || reviewID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review action path")
	}
	return cellID, reviewID, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealPath(path string, suffix string) (cellID string, appealReviewID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals" {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal action path")
	}
	cellID = strings.TrimSpace(parts[0])
	appealReviewID = strings.TrimSpace(parts[3])
	if cellID == "" || appealReviewID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal action path")
	}
	return cellID, appealReviewID, nil
}

func parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealPath(path string, suffix string) (cellID string, snapshotID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation counterparty incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation counterparty incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeals" {
		return "", "", fmt.Errorf("invalid secure cell federation counterparty incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal action path")
	}
	cellID = strings.TrimSpace(parts[0])
	snapshotID = strings.TrimSpace(parts[3])
	if cellID == "" || snapshotID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation counterparty incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal action path")
	}
	return cellID, snapshotID, nil
}

func parseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealPath(path string, suffix string) (cellID string, responseAppealID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals" {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal action path")
	}
	cellID = strings.TrimSpace(parts[0])
	responseAppealID = strings.TrimSpace(parts[3])
	if cellID == "" || responseAppealID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal action path")
	}
	return cellID, responseAppealID, nil
}

func parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealPath(path string, suffix string) (cellID string, snapshotID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation counterparty incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation counterparty incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeals" {
		return "", "", fmt.Errorf("invalid secure cell federation counterparty incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal action path")
	}
	cellID = strings.TrimSpace(parts[0])
	snapshotID = strings.TrimSpace(parts[3])
	if cellID == "" || snapshotID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation counterparty incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal action path")
	}
	return cellID, snapshotID, nil
}

func parseSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAppealReviewBundlePath(path string, suffix string) (cellID string, snapshotID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation counterparty incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal review bundle path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation counterparty incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal review bundle action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-appeal-review-bundles" {
		return "", "", fmt.Errorf("invalid secure cell federation counterparty incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal review bundle action path")
	}
	cellID = strings.TrimSpace(parts[0])
	snapshotID = strings.TrimSpace(parts[3])
	if cellID == "" || snapshotID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation counterparty incident directive extension appeal reconciliation challenge appeal alignment response appeal counterparty review appeal review appeal review bundle action path")
	}
	return cellID, snapshotID, nil
}

func parseSecureCellFederationIncidentReportAmendmentReconciliationActionPath(path string, suffix string) (cellID string, comparisonKey string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation incident report amendment reconciliation path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation incident report amendment reconciliation action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "incident-report-amendment-reconciliations" {
		return "", "", fmt.Errorf("invalid secure cell federation incident report amendment reconciliation action path")
	}
	cellID = strings.TrimSpace(parts[0])
	comparisonKey, err = url.PathUnescape(strings.TrimSpace(parts[3]))
	if err != nil {
		return "", "", fmt.Errorf("invalid secure cell federation incident report amendment reconciliation key: %w", err)
	}
	if cellID == "" || strings.TrimSpace(comparisonKey) == "" {
		return "", "", fmt.Errorf("invalid secure cell federation incident report amendment reconciliation action path")
	}
	return cellID, strings.TrimSpace(comparisonKey), nil
}

func parseSecureCellFederationContractActionPath(path string, suffix string) (cellID string, contractID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation contract path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation contract action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "contracts" {
		return "", "", fmt.Errorf("invalid secure cell federation contract action path")
	}
	cellID = strings.TrimSpace(parts[0])
	contractID = strings.TrimSpace(parts[3])
	if cellID == "" || contractID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation contract action path")
	}
	return cellID, contractID, nil
}

func parseSecureCellFederationCounterproposalActionPath(path string, suffix string) (cellID string, counterproposalID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell federation counterproposal path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell federation counterproposal action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "federation" || parts[2] != "counterproposals" {
		return "", "", fmt.Errorf("invalid secure cell federation counterproposal action path")
	}
	cellID = strings.TrimSpace(parts[0])
	counterproposalID = strings.TrimSpace(parts[3])
	if cellID == "" || counterproposalID == "" {
		return "", "", fmt.Errorf("invalid secure cell federation counterproposal action path")
	}
	return cellID, counterproposalID, nil
}

func parseSecureCellSessionActionPath(path string, suffix string) (cellID string, sessionID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", fmt.Errorf("invalid secure cell session path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", fmt.Errorf("invalid secure cell session action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 3 || parts[1] != "sessions" {
		return "", "", fmt.Errorf("invalid secure cell session action path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	if cellID == "" || sessionID == "" {
		return "", "", fmt.Errorf("invalid secure cell session action path")
	}
	return cellID, sessionID, nil
}

func parseSecureCellSessionLifecycleActionPath(path string) (cellID string, sessionID string, action string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", fmt.Errorf("invalid secure cell session lifecycle path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 4 || parts[1] != "sessions" {
		return "", "", "", fmt.Errorf("invalid secure cell session lifecycle path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	action = strings.TrimSpace(parts[3])
	if cellID == "" || sessionID == "" || action == "" {
		return "", "", "", fmt.Errorf("invalid secure cell session lifecycle path")
	}
	return cellID, sessionID, action, nil
}

func parseSecureCellSessionMemberActionPath(path string, suffix string) (cellID string, sessionID string, participantDID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", fmt.Errorf("invalid secure cell session member path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", "", fmt.Errorf("invalid secure cell session member action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 5 || parts[1] != "sessions" || parts[3] != "members" {
		return "", "", "", fmt.Errorf("invalid secure cell session member action path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	participantDID = strings.TrimSpace(parts[4])
	if cellID == "" || sessionID == "" || participantDID == "" {
		return "", "", "", fmt.Errorf("invalid secure cell session member action path")
	}
	return cellID, sessionID, participantDID, nil
}

func parseSecureCellSessionThreadActionPath(path string, suffix string) (cellID string, sessionID string, threadID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", fmt.Errorf("invalid secure cell session thread path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", "", fmt.Errorf("invalid secure cell session thread action path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 5 || parts[1] != "sessions" || parts[3] != "threads" {
		return "", "", "", fmt.Errorf("invalid secure cell session thread action path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	threadID = strings.TrimSpace(parts[4])
	if cellID == "" || sessionID == "" || threadID == "" {
		return "", "", "", fmt.Errorf("invalid secure cell session thread action path")
	}
	return cellID, sessionID, threadID, nil
}

func parseSecureCellSessionThreadLifecycleActionPath(path string) (cellID string, sessionID string, threadID string, action string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", "", fmt.Errorf("invalid secure cell session thread lifecycle path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 6 || parts[1] != "sessions" || parts[3] != "threads" {
		return "", "", "", "", fmt.Errorf("invalid secure cell session thread lifecycle path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	threadID = strings.TrimSpace(parts[4])
	action = strings.TrimSpace(parts[5])
	if cellID == "" || sessionID == "" || threadID == "" || action == "" {
		return "", "", "", "", fmt.Errorf("invalid secure cell session thread lifecycle path")
	}
	return cellID, sessionID, threadID, action, nil
}

func parseSecureCellSessionThreadDecisionLifecycleActionPath(path string) (cellID string, sessionID string, threadID string, decisionID string, action string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", "", "", fmt.Errorf("invalid secure cell thread decision lifecycle path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 8 || parts[1] != "sessions" || parts[3] != "threads" || parts[5] != "decisions" {
		return "", "", "", "", "", fmt.Errorf("invalid secure cell thread decision lifecycle path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	threadID = strings.TrimSpace(parts[4])
	decisionID = strings.TrimSpace(parts[6])
	action = strings.TrimSpace(parts[7])
	if cellID == "" || sessionID == "" || threadID == "" || decisionID == "" || action == "" {
		return "", "", "", "", "", fmt.Errorf("invalid secure cell thread decision lifecycle path")
	}
	return cellID, sessionID, threadID, decisionID, action, nil
}

func parseSecureCellSessionThreadDecisionOutcomeBundleFetchPath(path string) (cellID string, sessionID string, threadID string, decisionID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", "", fmt.Errorf("invalid secure cell thread decision outcome bundle path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 9 || parts[1] != "sessions" || parts[3] != "threads" || parts[5] != "decisions" || parts[8] != "fetch" || parts[7] != "outcome-bundles" {
		return "", "", "", "", fmt.Errorf("invalid secure cell thread decision outcome bundle path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	threadID = strings.TrimSpace(parts[4])
	decisionID = strings.TrimSpace(parts[6])
	if cellID == "" || sessionID == "" || threadID == "" || decisionID == "" {
		return "", "", "", "", fmt.Errorf("invalid secure cell thread decision outcome bundle path")
	}
	return cellID, sessionID, threadID, decisionID, nil
}

func parseSecureCellSessionThreadDecisionLookupPath(path string, suffix string) (cellID string, sessionID string, threadID string, decisionID string, err error) {
	if !strings.HasPrefix(path, secureCellsItemPrefix) {
		return "", "", "", "", fmt.Errorf("invalid secure cell thread decision path")
	}
	remainder := strings.TrimPrefix(path, secureCellsItemPrefix)
	if suffix != "" {
		if !strings.HasSuffix(remainder, suffix) {
			return "", "", "", "", fmt.Errorf("invalid secure cell thread decision path")
		}
		remainder = strings.TrimSuffix(remainder, suffix)
	}
	parts := strings.Split(strings.Trim(remainder, "/"), "/")
	if len(parts) != 7 || parts[1] != "sessions" || parts[3] != "threads" || parts[5] != "decisions" {
		return "", "", "", "", fmt.Errorf("invalid secure cell thread decision path")
	}
	cellID = strings.TrimSpace(parts[0])
	sessionID = strings.TrimSpace(parts[2])
	threadID = strings.TrimSpace(parts[4])
	decisionID = strings.TrimSpace(parts[6])
	if cellID == "" || sessionID == "" || threadID == "" || decisionID == "" {
		return "", "", "", "", fmt.Errorf("invalid secure cell thread decision path")
	}
	return cellID, sessionID, threadID, decisionID, nil
}

func cloneStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func containsString(values []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func secureCellDecisionMutationMetadata(metadata map[string]string, decisionID, comment string, relatedOutputIDs []string, approvalThreshold *int, approvalVote string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	if trimmed := strings.TrimSpace(decisionID); trimmed != "" {
		out["decision_id"] = trimmed
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["decision_comment"] = trimmed
	}
	if len(relatedOutputIDs) > 0 {
		outputs := make([]string, 0, len(relatedOutputIDs))
		for _, outputID := range relatedOutputIDs {
			if trimmed := strings.TrimSpace(outputID); trimmed != "" {
				outputs = append(outputs, trimmed)
			}
		}
		if len(outputs) > 0 {
			out["related_output_ids"] = strings.Join(outputs, ",")
		}
	}
	if approvalThreshold != nil {
		out["approval_threshold"] = fmt.Sprintf("%d", *approvalThreshold)
	}
	if trimmed := strings.TrimSpace(approvalVote); trimmed != "" {
		out["approval_vote"] = trimmed
	}
	return out
}

func secureCellDecisionGovernanceMetadata(metadata map[string]string, deadlineAt *time.Time, policyTemplate string, autoEscalation *bool) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	if deadlineAt != nil && !deadlineAt.IsZero() {
		out["decision_deadline_at"] = deadlineAt.UTC().Format(time.RFC3339Nano)
	}
	if trimmed := strings.TrimSpace(policyTemplate); trimmed != "" {
		out["decision_policy_template"] = trimmed
	}
	if autoEscalation != nil {
		out["decision_auto_escalation_enabled"] = fmt.Sprintf("%t", *autoEscalation)
	}
	return out
}

func secureCellDecisionApprovalMetadata(metadata map[string]string, threshold *int, vote string, comment string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	if threshold != nil {
		out["approval_threshold"] = fmt.Sprintf("%d", *threshold)
	}
	if trimmed := strings.TrimSpace(vote); trimmed != "" {
		out["approval_vote"] = trimmed
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["approval_comment"] = trimmed
	}
	return out
}

func secureCellDecisionVoteMetadata(metadata map[string]string, threshold *int, voteChoice string, voteRole string, comment string) map[string]string {
	out := secureCellDecisionApprovalMetadata(metadata, threshold, voteChoice, comment)
	if trimmed := strings.TrimSpace(voteChoice); trimmed != "" {
		out["decision_vote_choice"] = trimmed
		out["approval_vote"] = trimmed
	}
	if trimmed := strings.TrimSpace(voteRole); trimmed != "" {
		out["decision_vote_role"] = trimmed
	}
	return out
}

func secureCellDecisionDelegationMetadata(metadata map[string]string, decisionID, delegatedToDID, comment, reason string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	if trimmed := strings.TrimSpace(decisionID); trimmed != "" {
		out["decision_id"] = trimmed
	}
	if trimmed := strings.TrimSpace(delegatedToDID); trimmed != "" {
		out["decision_delegated_to_did"] = trimmed
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["decision_comment"] = trimmed
	}
	if trimmed := strings.TrimSpace(reason); trimmed != "" {
		out["decision_delegation_reason"] = trimmed
	}
	return out
}

func secureCellDecisionEscalationMetadata(metadata map[string]string, decisionID, escalationReason, comment, reason string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	if trimmed := strings.TrimSpace(decisionID); trimmed != "" {
		out["decision_id"] = trimmed
	}
	if trimmed := strings.TrimSpace(escalationReason); trimmed != "" {
		out["decision_escalation_reason"] = trimmed
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["decision_comment"] = trimmed
	}
	if trimmed := strings.TrimSpace(reason); trimmed != "" {
		out["decision_escalation_request_reason"] = trimmed
	}
	return out
}

func secureCellOutcomeBundleMetadata(metadata map[string]string, decisionID, outcomeBundleID, outcomeBundleName, outcomeBundleType, comment string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	if trimmed := strings.TrimSpace(decisionID); trimmed != "" {
		out["decision_id"] = trimmed
	}
	if trimmed := strings.TrimSpace(outcomeBundleID); trimmed != "" {
		out["decision_outcome_bundle_id"] = trimmed
	}
	if trimmed := strings.TrimSpace(outcomeBundleName); trimmed != "" {
		out["decision_outcome_bundle_name"] = trimmed
	}
	if trimmed := strings.TrimSpace(outcomeBundleType); trimmed != "" {
		out["decision_outcome_bundle_type"] = trimmed
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["decision_comment"] = trimmed
	}
	return out
}

func secureCellDecisionOutputContainmentMetadata(metadata map[string]string, relatedOutputIDs []string, comment string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	out["containment_mode"] = "decision_outputs"
	if len(relatedOutputIDs) > 0 {
		outputs := make([]string, 0, len(relatedOutputIDs))
		for _, outputID := range relatedOutputIDs {
			if trimmed := strings.TrimSpace(outputID); trimmed != "" {
				outputs = append(outputs, trimmed)
			}
		}
		if len(outputs) > 0 {
			out["related_output_ids"] = strings.Join(outputs, ",")
		}
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["containment_comment"] = trimmed
	}
	return out
}

func secureCellDecisionOutputReleaseMetadata(metadata map[string]string, relatedOutputIDs []string, comment string) map[string]string {
	out := cloneStringMap(metadata)
	if out == nil {
		out = make(map[string]string)
	}
	out["release_mode"] = "decision_outputs"
	if len(relatedOutputIDs) > 0 {
		outputs := make([]string, 0, len(relatedOutputIDs))
		for _, outputID := range relatedOutputIDs {
			if trimmed := strings.TrimSpace(outputID); trimmed != "" {
				outputs = append(outputs, trimmed)
			}
		}
		if len(outputs) > 0 {
			out["related_output_ids"] = strings.Join(outputs, ",")
		}
	}
	if trimmed := strings.TrimSpace(comment); trimmed != "" {
		out["release_comment"] = trimmed
	}
	return out
}

func secureCellErrorStatus(err error, fallback int) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, audit.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, audit.ErrWriteDisabled):
		return http.StatusServiceUnavailable
	case errors.Is(err, securecellsintegration.ErrCellNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrParticipantNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrParticipantExists):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrSessionNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrSessionNotActive):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrSessionImmutable):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrSessionParticipantNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrSessionParticipantExists):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrThreadNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrThreadNotActive):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrThreadImmutable):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrDecisionNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrDecisionNotActive):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrDecisionImmutable):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrFederationOrganizationNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrFederationContractNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrFederationInvitationNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrFederationCounterproposalNotFound):
		return http.StatusNotFound
	case errors.Is(err, securecellsintegration.ErrFederationInvitationImmutable):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrFederationCounterproposalImmutable):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrFederationContractImmutable):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrFederationContractSuspended):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrFederationNegotiationConflict):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrFederationContractRequired):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrFederationExchangePolicyDenied):
		return http.StatusForbidden
	case errors.Is(err, securecellsintegration.ErrCellImmutable):
		return http.StatusConflict
	case errors.Is(err, securecellsintegration.ErrPolicyDenied):
		return http.StatusForbidden
	default:
		return fallback
	}
}

func safeSecureCellActorDID(authCtx *secureCellAuthContext) string {
	if authCtx == nil {
		return ""
	}
	return strings.TrimSpace(authCtx.ActorDID)
}

func safeSecureCellOptionalInt(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func safeSecureCellOptionalTime(value *time.Time) *time.Time {
	if value == nil || value.IsZero() {
		return nil
	}
	normalized := value.UTC()
	return &normalized
}

func secureCellDecisionResolutionDueAt(req secureCellThreadDecisionRequest) *time.Time {
	if normalized := safeSecureCellOptionalTime(req.ResolutionDueAt); normalized != nil {
		return normalized
	}
	return safeSecureCellOptionalTime(req.DeadlineAt)
}

func secureCellDecisionServiceGovernanceTemplate(req secureCellThreadDecisionRequest) string {
	if template := strings.TrimSpace(req.GovernanceTemplate); template != "" {
		return template
	}
	switch normalized := strings.ToLower(strings.TrimSpace(req.PolicyTemplate)); normalized {
	case "standard_review", "dual_control", "board_escalation":
		return normalized
	default:
		return ""
	}
}

func secureCellDecisionServiceSLATemplate(req secureCellThreadDecisionRequest) string {
	if template := strings.TrimSpace(req.SLATemplate); template != "" {
		return strings.ToLower(template)
	}
	return ""
}

func secureCellDecisionServiceSectorPolicyPack(req secureCellThreadDecisionRequest) string {
	if pack := strings.TrimSpace(req.SectorPolicyPack); pack != "" {
		return strings.ToLower(pack)
	}
	return ""
}

func writeSecureCellAPIError(w http.ResponseWriter, status int, message string) {
	writeSecureCellJSON(w, status, secureCellAPIErrorResponse{Error: message})
}

func writeSecureCellJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
