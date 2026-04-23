package securecells

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus
// captures signature and freshness posture for one imported signed bilateral
// imported-ruling appeal-board bundle.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus string

const (
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatusVerified SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus = "verified"
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatusStale    SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus = "stale"
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatusExpired  SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus = "expired"
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatusInvalid  SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus = "invalid"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus
// captures local governed review posture over one imported signed bilateral
// imported-ruling appeal-board bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusUnreviewed   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus = "unreviewed"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusAcknowledged SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus = "acknowledged"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusDisputed     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus = "disputed"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusEscalated    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus = "escalated"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusResolved     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus = "resolved"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType
// records one evidence-bearing local response to an imported signed bilateral
// imported-ruling appeal-board bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionAcknowledge SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType = "acknowledge_counterparty_appeal_ruling"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionDispute     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType = "dispute_counterparty_appeal_ruling"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionEscalate    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType = "escalate_counterparty_appeal_ruling_dispute"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionResolve     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType = "resolve_counterparty_appeal_ruling_dispute"
)

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSnapshot
// persists one imported signed bilateral imported-ruling appeal-board bundle in
// the secure-cell trace.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSnapshot struct {
	SnapshotID          string                                                                                                                                             `json:"snapshot_id"`
	OrganizationID      string                                                                                                                                             `json:"organization_id"`
	Bundle              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle             `json:"bundle"`
	Status              SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus `json:"status"`
	Verified            bool                                                                                                                                               `json:"verified"`
	VerificationMessage string                                                                                                                                             `json:"verification_message,omitempty"`
	Signer              string                                                                                                                                             `json:"signer,omitempty"`
	ReceivedBy          string                                                                                                                                             `json:"received_by,omitempty"`
	ReceivedAt          time.Time                                                                                                                                          `json:"received_at"`
	Metadata            map[string]string                                                                                                                                  `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleIntakeRequest
// ingests one signed bilateral imported-ruling appeal-board bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleIntakeRequest struct {
	ActorDID string                                                                                                                                  `json:"actor_did,omitempty"`
	Bundle   *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle `json:"bundle,omitempty"`
	Reason   string                                                                                                                                  `json:"reason,omitempty"`
	Metadata map[string]string                                                                                                                       `json:"metadata,omitempty"`
}

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter
// narrows operator queries across imported signed bilateral imported-ruling
// appeal-board bundles.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter struct {
	CellID                            string                                                                                                                                             `json:"cell_id,omitempty"`
	OrganizationID                    string                                                                                                                                             `json:"organization_id,omitempty"`
	IncidentID                        string                                                                                                                                             `json:"incident_id,omitempty"`
	ResponseID                        string                                                                                                                                             `json:"response_id,omitempty"`
	DirectiveID                       string                                                                                                                                             `json:"directive_id,omitempty"`
	ExtensionID                       string                                                                                                                                             `json:"extension_id,omitempty"`
	DisputeID                         string                                                                                                                                             `json:"dispute_id,omitempty"`
	AppealID                          string                                                                                                                                             `json:"appeal_id,omitempty"`
	ChallengeID                       string                                                                                                                                             `json:"challenge_id,omitempty"`
	ChallengeAppealID                 string                                                                                                                                             `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID                  string                                                                                                                                             `json:"response_appeal_id,omitempty"`
	SnapshotID                        string                                                                                                                                             `json:"snapshot_id,omitempty"`
	CounterpartyReviewID              string                                                                                                                                             `json:"counterparty_review_id,omitempty"`
	CounterpartyReviewAppealID        string                                                                                                                                             `json:"counterparty_review_appeal_id,omitempty"`
	CounterpartyBoardResponseAppealID string                                                                                                                                             `json:"counterparty_board_response_appeal_id,omitempty"`
	Status                            SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus `json:"status,omitempty"`
	ReviewStatus                      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus       `json:"review_status,omitempty"`
	Limit                             int                                                                                                                                                `json:"limit,omitempty"`
}

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary
// projects one imported signed bilateral imported-ruling appeal-board bundle
// together with local governed review posture.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary struct {
	CellID                                string                                                                                                                                             `json:"cell_id"`
	CellName                              string                                                                                                                                             `json:"cell_name,omitempty"`
	CellStatus                            SecureCellStatus                                                                                                                                   `json:"cell_status"`
	Jurisdiction                          string                                                                                                                                             `json:"jurisdiction,omitempty"`
	OrganizationID                        string                                                                                                                                             `json:"organization_id"`
	SponsorOfRecord                       string                                                                                                                                             `json:"sponsor_of_record,omitempty"`
	OrganizationName                      string                                                                                                                                             `json:"organization_name,omitempty"`
	SnapshotID                            string                                                                                                                                             `json:"snapshot_id"`
	BundleID                              string                                                                                                                                             `json:"bundle_id,omitempty"`
	BundleVersion                         string                                                                                                                                             `json:"bundle_version,omitempty"`
	BundleName                            string                                                                                                                                             `json:"bundle_name,omitempty"`
	Status                                SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus `json:"status"`
	Verified                              bool                                                                                                                                               `json:"verified"`
	Signer                                string                                                                                                                                             `json:"signer,omitempty"`
	KeyID                                 string                                                                                                                                             `json:"key_id,omitempty"`
	IncidentID                            string                                                                                                                                             `json:"incident_id,omitempty"`
	ResponseID                            string                                                                                                                                             `json:"response_id,omitempty"`
	DirectiveID                           string                                                                                                                                             `json:"directive_id,omitempty"`
	ExtensionID                           string                                                                                                                                             `json:"extension_id,omitempty"`
	DisputeID                             string                                                                                                                                             `json:"dispute_id,omitempty"`
	AppealID                              string                                                                                                                                             `json:"appeal_id,omitempty"`
	ChallengeID                           string                                                                                                                                             `json:"challenge_id,omitempty"`
	ChallengeAppealID                     string                                                                                                                                             `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID                      string                                                                                                                                             `json:"response_appeal_id,omitempty"`
	ResponseAppealStatus                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                                     `json:"response_appeal_status,omitempty"`
	ResponseStatus                        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                                           `json:"response_status,omitempty"`
	ResponseAction                        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                                       `json:"response_action,omitempty"`
	ResponseTransitionID                  string                                                                                                                                             `json:"response_transition_id,omitempty"`
	LocalRuling                           SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                                         `json:"local_ruling,omitempty"`
	CounterpartyReviewID                  string                                                                                                                                             `json:"counterparty_review_id,omitempty"`
	CounterpartyReviewAppealID            string                                                                                                                                             `json:"counterparty_review_appeal_id,omitempty"`
	CounterpartyReviewStatus              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus                   `json:"counterparty_review_status,omitempty"`
	CounterpartyReviewAction              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType                     `json:"counterparty_review_action,omitempty"`
	CounterpartyReviewReference           string                                                                                                                                             `json:"counterparty_review_reference,omitempty"`
	CounterpartyBoardResponseAppealID     string                                                                                                                                             `json:"counterparty_board_response_appeal_id,omitempty"`
	CounterpartyBoardResponseAppealStatus SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                                     `json:"counterparty_board_response_appeal_status,omitempty"`
	CounterpartyBoardResponseStatus       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                                           `json:"counterparty_board_response_status,omitempty"`
	CounterpartyBoardResponseAction       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                                       `json:"counterparty_board_response_action,omitempty"`
	CounterpartyBoardResponseTransitionID string                                                                                                                                             `json:"counterparty_board_response_transition_id,omitempty"`
	CounterpartyBoardRuling               SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                                         `json:"counterparty_board_ruling,omitempty"`
	AlignmentStatus                       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus                                                   `json:"alignment_status,omitempty"`
	AlignmentDivergenceCount              int                                                                                                                                                `json:"alignment_divergence_count"`
	ReviewStatus                          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus       `json:"review_status"`
	LastReviewedBy                        string                                                                                                                                             `json:"last_reviewed_by,omitempty"`
	LastReviewedAt                        *time.Time                                                                                                                                         `json:"last_reviewed_at,omitempty"`
	ReviewActionCount                     int                                                                                                                                                `json:"review_action_count"`
	GeneratedAt                           time.Time                                                                                                                                          `json:"generated_at"`
	ExpiresAt                             *time.Time                                                                                                                                         `json:"expires_at,omitempty"`
	ReceivedAt                            time.Time                                                                                                                                          `json:"received_at"`
	ControlLedgerID                       string                                                                                                                                             `json:"control_ledger_id,omitempty"`
	ControlLedgerHash                     string                                                                                                                                             `json:"control_ledger_hash,omitempty"`
	PortablePackageHash                   string                                                                                                                                             `json:"portable_package_hash,omitempty"`
	PortablePackageSigned                 bool                                                                                                                                               `json:"portable_package_signed"`
	PortablePackageAnchored               bool                                                                                                                                               `json:"portable_package_anchored"`
	VerificationMessage                   string                                                                                                                                             `json:"verification_message,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewFilter
// narrows operator queries across local review actions over imported signed
// bilateral imported-ruling appeal-board bundles.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewFilter struct {
	CellID                            string                                                                                                                                             `json:"cell_id,omitempty"`
	OrganizationID                    string                                                                                                                                             `json:"organization_id,omitempty"`
	IncidentID                        string                                                                                                                                             `json:"incident_id,omitempty"`
	ResponseID                        string                                                                                                                                             `json:"response_id,omitempty"`
	DirectiveID                       string                                                                                                                                             `json:"directive_id,omitempty"`
	ExtensionID                       string                                                                                                                                             `json:"extension_id,omitempty"`
	DisputeID                         string                                                                                                                                             `json:"dispute_id,omitempty"`
	AppealID                          string                                                                                                                                             `json:"appeal_id,omitempty"`
	ChallengeID                       string                                                                                                                                             `json:"challenge_id,omitempty"`
	ChallengeAppealID                 string                                                                                                                                             `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID                  string                                                                                                                                             `json:"response_appeal_id,omitempty"`
	SnapshotID                        string                                                                                                                                             `json:"snapshot_id,omitempty"`
	CounterpartyReviewAppealID        string                                                                                                                                             `json:"counterparty_review_appeal_id,omitempty"`
	CounterpartyBoardResponseAppealID string                                                                                                                                             `json:"counterparty_board_response_appeal_id,omitempty"`
	Status                            SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus `json:"status,omitempty"`
	ReviewStatus                      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus       `json:"review_status,omitempty"`
	Action                            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType   `json:"action,omitempty"`
	ActorDID                          string                                                                                                                                             `json:"actor_did,omitempty"`
	Limit                             int                                                                                                                                                `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord
// projects one local evidence-bearing acknowledgement or dispute over an
// imported signed bilateral imported-ruling appeal-board bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord struct {
	CellID                                string                                                                                                                                             `json:"cell_id"`
	CellName                              string                                                                                                                                             `json:"cell_name,omitempty"`
	CellStatus                            SecureCellStatus                                                                                                                                   `json:"cell_status"`
	Jurisdiction                          string                                                                                                                                             `json:"jurisdiction,omitempty"`
	OrganizationID                        string                                                                                                                                             `json:"organization_id"`
	SponsorOfRecord                       string                                                                                                                                             `json:"sponsor_of_record,omitempty"`
	OrganizationName                      string                                                                                                                                             `json:"organization_name,omitempty"`
	IncidentID                            string                                                                                                                                             `json:"incident_id,omitempty"`
	ResponseID                            string                                                                                                                                             `json:"response_id,omitempty"`
	DirectiveID                           string                                                                                                                                             `json:"directive_id,omitempty"`
	ExtensionID                           string                                                                                                                                             `json:"extension_id,omitempty"`
	DisputeID                             string                                                                                                                                             `json:"dispute_id,omitempty"`
	AppealID                              string                                                                                                                                             `json:"appeal_id,omitempty"`
	ChallengeID                           string                                                                                                                                             `json:"challenge_id,omitempty"`
	ChallengeAppealID                     string                                                                                                                                             `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID                      string                                                                                                                                             `json:"response_appeal_id,omitempty"`
	ResponseAppealStatus                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                                     `json:"response_appeal_status,omitempty"`
	ResponseStatus                        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                                           `json:"response_status,omitempty"`
	ResponseAction                        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                                       `json:"response_action,omitempty"`
	ResponseTransitionID                  string                                                                                                                                             `json:"response_transition_id,omitempty"`
	LocalRuling                           SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                                         `json:"local_ruling,omitempty"`
	SnapshotID                            string                                                                                                                                             `json:"snapshot_id"`
	BundleID                              string                                                                                                                                             `json:"bundle_id,omitempty"`
	CounterpartyReviewID                  string                                                                                                                                             `json:"counterparty_review_id,omitempty"`
	CounterpartyReviewAppealID            string                                                                                                                                             `json:"counterparty_review_appeal_id,omitempty"`
	CounterpartyReviewStatus              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus                   `json:"counterparty_review_status,omitempty"`
	CounterpartyReviewAction              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType                     `json:"counterparty_review_action,omitempty"`
	CounterpartyReviewReference           string                                                                                                                                             `json:"counterparty_review_reference,omitempty"`
	CounterpartyBoardResponseAppealID     string                                                                                                                                             `json:"counterparty_board_response_appeal_id,omitempty"`
	CounterpartyBoardResponseAppealStatus SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                                     `json:"counterparty_board_response_appeal_status,omitempty"`
	CounterpartyBoardResponseStatus       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                                           `json:"counterparty_board_response_status,omitempty"`
	CounterpartyBoardResponseAction       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                                       `json:"counterparty_board_response_action,omitempty"`
	CounterpartyBoardResponseTransitionID string                                                                                                                                             `json:"counterparty_board_response_transition_id,omitempty"`
	CounterpartyBoardRuling               SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                                         `json:"counterparty_board_ruling,omitempty"`
	Status                                SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus `json:"status,omitempty"`
	ReviewStatus                          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus       `json:"review_status"`
	Action                                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType   `json:"action"`
	AlignmentStatus                       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus                                                   `json:"alignment_status,omitempty"`
	AlignmentDivergenceCount              int                                                                                                                                                `json:"alignment_divergence_count"`
	Divergences                           []string                                                                                                                                           `json:"divergences,omitempty"`
	TransitionID                          string                                                                                                                                             `json:"transition_id,omitempty"`
	PolicyReceiptID                       string                                                                                                                                             `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash                     string                                                                                                                                             `json:"policy_receipt_hash,omitempty"`
	SealID                                string                                                                                                                                             `json:"seal_id,omitempty"`
	TraceLinkID                           string                                                                                                                                             `json:"trace_link_id,omitempty"`
	ActorDID                              string                                                                                                                                             `json:"actor_did,omitempty"`
	Reason                                string                                                                                                                                             `json:"reason,omitempty"`
	Metadata                              map[string]string                                                                                                                                  `json:"metadata,omitempty"`
	OccurredAt                            time.Time                                                                                                                                          `json:"occurred_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledgeRequest
// acknowledges one imported signed bilateral imported-ruling appeal-board bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledgeRequest struct {
	ActorDID              string            `json:"actor_did,omitempty"`
	SnapshotID            string            `json:"snapshot_id,omitempty"`
	CounterpartyReference string            `json:"counterparty_reference,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeRequest
// disputes one imported signed bilateral imported-ruling appeal-board bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeRequest struct {
	ActorDID              string            `json:"actor_did,omitempty"`
	SnapshotID            string            `json:"snapshot_id,omitempty"`
	CounterpartyReference string            `json:"counterparty_reference,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Divergences           []string          `json:"divergences,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeEscalationRequest
// opens a fresh local rehearing generation after a disputed imported signed
// bilateral imported-ruling appeal-board bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeEscalationRequest struct {
	ActorDID                            string                                    `json:"actor_did,omitempty"`
	SnapshotID                          string                                    `json:"snapshot_id,omitempty"`
	CounterpartyReference               string                                    `json:"counterparty_reference,omitempty"`
	AppealingParty                      SecureCellFederationIncidentResponseParty `json:"appealing_party,omitempty"`
	CorrectionBoardParty                SecureCellFederationIncidentResponseParty `json:"correction_board_party,omitempty"`
	EnforcementAcknowledgementParty     SecureCellFederationIncidentResponseParty `json:"enforcement_acknowledgement_party,omitempty"`
	Summary                             string                                    `json:"summary,omitempty"`
	Description                         string                                    `json:"description,omitempty"`
	EvidenceIDs                         []string                                  `json:"evidence_ids,omitempty"`
	Divergences                         []string                                  `json:"divergences,omitempty"`
	CorrectionBoardReviewThreshold      int                                       `json:"correction_board_review_threshold,omitempty"`
	EligibleCorrectionBoardReviewerDIDs []string                                  `json:"eligible_correction_board_reviewer_dids,omitempty"`
	Reason                              string                                    `json:"reason,omitempty"`
	Metadata                            map[string]string                         `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionSpec struct {
	stage                 string
	action                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType
	reviewStatus          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus
	actorDID              string
	snapshotID            string
	counterpartyReference string
	reason                string
	divergences           []string
	metadata              map[string]string
}

func (s *Service) IngestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(ctx context.Context, cellID string, organizationID string, intake SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleIntakeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, organizationID)
	if err != nil {
		return nil, err
	}
	if intake.Bundle == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: bundle is required")
	}
	bundle := secureCellCloneFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(*intake.Bundle)
	actorDID := firstNonEmpty(strings.TrimSpace(intake.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: %w: actor %q is not permitted to intake reciprocal imported-ruling appeal-board bundles", ErrPolicyDenied, actorDID)
	}

	verificationErr := VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(&bundle)
	if verificationErr == nil {
		verificationErr = secureCellValidateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSemantics(&bundle, strings.TrimSpace(orgSummary.OrganizationID))
	}
	now := time.Now().UTC()
	status, verificationMessage, verified := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleStatusAt(&bundle, verificationErr, now)

	localAppealID := strings.TrimSpace(bundle.CounterpartyAppeal.ResponseAppealID)
	if localAppealID == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: local response appeal reference is required")
	}
	if _, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, localAppealID); err != nil {
		return nil, err
	}

	receipt, err := s.evaluateStage(ctx, run.request, "intake_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_bundle", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":   strings.TrimSpace(orgSummary.OrganizationID),
		"federation_sponsor_of_record": strings.TrimSpace(orgSummary.SponsorOfRecord),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                                                          strings.TrimSpace(bundle.CounterpartyAppeal.ChallengeAppealID),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":                                strings.TrimSpace(bundle.CounterpartyAppeal.ResponseAppealID),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_id":     strings.TrimSpace(bundle.ReviewAppeal.AppealReviewID),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_status": string(status),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_signer": secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSignerName(&bundle),
		"transition_reason": strings.TrimSpace(intake.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: %w", ErrPolicyDenied)
	}

	snapshot := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSnapshot{
		SnapshotID:          fmt.Sprintf("%s-federation-counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-%x", strings.TrimSpace(cellID), sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", strings.TrimSpace(orgSummary.OrganizationID), strings.TrimSpace(bundle.ID), now.Format(time.RFC3339Nano))))),
		OrganizationID:      strings.TrimSpace(orgSummary.OrganizationID),
		Bundle:              bundle,
		Status:              status,
		Verified:            verified,
		VerificationMessage: strings.TrimSpace(verificationMessage),
		Signer:              secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSignerName(&bundle),
		ReceivedBy:          actorDID,
		ReceivedAt:          now,
		Metadata:            cloneStringMap(intake.Metadata),
	}
	run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals = append(run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals, snapshot)
	run.result.UpdatedAt = receipt.EvaluatedAt.UTC()

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_bundle_ingested", snapshot.SnapshotID),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_bundle_ingested",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_bundle",
		TargetDID:        snapshot.SnapshotID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(intake.Reason),
		Metadata: mergeStringMaps(intake.Metadata, map[string]string{
			"federation_organization_id":                                                        snapshot.OrganizationID,
			"federation_sponsor_of_record":                                                      strings.TrimSpace(orgSummary.SponsorOfRecord),
			"federation_organization_name":                                                      strings.TrimSpace(orgSummary.OrganizationName),
			"federation_incident_id":                                                            strings.TrimSpace(bundle.CounterpartyAppeal.IncidentID),
			"federation_incident_response_id":                                                   strings.TrimSpace(bundle.CounterpartyAppeal.ResponseID),
			"federation_incident_directive_id":                                                  strings.TrimSpace(bundle.CounterpartyAppeal.DirectiveID),
			"federation_incident_directive_extension_id":                                        strings.TrimSpace(bundle.CounterpartyAppeal.ExtensionID),
			"federation_incident_directive_extension_dispute_id":                                strings.TrimSpace(bundle.CounterpartyAppeal.DisputeID),
			"federation_incident_directive_extension_appeal_id":                                 strings.TrimSpace(bundle.CounterpartyAppeal.AppealID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":        strings.TrimSpace(bundle.CounterpartyAppeal.ChallengeID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id": strings.TrimSpace(bundle.CounterpartyAppeal.ChallengeAppealID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":                                                                   strings.TrimSpace(bundle.CounterpartyAppeal.ResponseAppealID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_snapshot_id":                               snapshot.SnapshotID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_bundle_id":                                 strings.TrimSpace(bundle.ID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_id":                                               strings.TrimSpace(bundle.Review.ReviewID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_id":                                        strings.TrimSpace(bundle.ReviewAppeal.AppealReviewID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_status":                                    string(status),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_status":                                           string(bundle.Review.ReviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_action":                                           string(bundle.Review.LatestReviewAction),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_reference":                                        strings.TrimSpace(bundle.Review.CounterpartyReference),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_board_response_appeal_id":     strings.TrimSpace(bundle.ReviewAppeal.BoardResponseAppealID),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_board_response_appeal_status": string(bundle.ReviewAppeal.BoardResponseAppealStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_board_ruling":                 string(bundle.ReviewAppeal.BoardRuling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_signer":                                    secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSignerName(&bundle),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals(_ context.Context, filter SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter) ([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals {
			item := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummaryFromSnapshot(run, snapshot)
			if !matchesSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter(item, filter) {
				continue
			}
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ReceivedAt.Equal(items[j].ReceivedAt) {
			return items[i].SnapshotID > items[j].SnapshotID
		}
		return items[i].ReceivedAt.After(items[j].ReceivedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) GetFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(_ context.Context, cellID string, snapshotID string) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals {
		if strings.EqualFold(strings.TrimSpace(snapshot.SnapshotID), strings.TrimSpace(snapshotID)) {
			bundle := secureCellCloneFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(snapshot.Bundle)
			return &bundle, nil
		}
	}
	return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: %w: counterparty review appeal snapshot %q", ErrFederationIncidentDirectiveNotFound, snapshotID)
}

func (s *Service) AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealRuling(ctx context.Context, cellID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAcknowledgeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAction(ctx, cellID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionSpec{
		stage:                 "acknowledge_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_ruling",
		action:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionAcknowledge,
		reviewStatus:          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusAcknowledged,
		actorDID:              req.ActorDID,
		snapshotID:            req.SnapshotID,
		counterpartyReference: req.CounterpartyReference,
		reason:                req.Reason,
		metadata:              req.Metadata,
	})
}

func (s *Service) DisputeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealRuling(ctx context.Context, cellID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAction(ctx, cellID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionSpec{
		stage:                 "dispute_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_ruling",
		action:                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionDispute,
		reviewStatus:          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusDisputed,
		actorDID:              req.ActorDID,
		snapshotID:            req.SnapshotID,
		counterpartyReference: req.CounterpartyReference,
		reason:                req.Reason,
		divergences:           req.Divergences,
		metadata:              req.Metadata,
	})
}

// EscalateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDispute
// opens a fresh governed rehearing over the latest local appeal-board response
// after a disputed imported reciprocal appeal-board ruling.
func (s *Service) EscalateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDispute(ctx context.Context, cellID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDisputeEscalationRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, err := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummaryBySnapshot(run, strings.TrimSpace(req.SnapshotID))
	if err != nil {
		return nil, err
	}
	localBoardResponseAppealID := strings.TrimSpace(summary.CounterpartyBoardResponseAppealID)
	if localBoardResponseAppealID == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: %w: imported reciprocal appeal-board snapshot %q does not carry a local board-response appeal", ErrFederationIncidentDirectiveNotFound, summary.SnapshotID)
	}
	localBoardAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, localBoardResponseAppealID)
	if err != nil {
		return nil, err
	}
	latestReview := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAction(run, summary.SnapshotID)
	if latestReview == nil || latestReview.ReviewStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusDisputed {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: %w: disputed imported reciprocal appeal-board ruling is required before escalation for snapshot %q", ErrFederationIncidentDirectiveImmutable, summary.SnapshotID)
	}
	divergences := uniqueTrimmedStrings(append(append([]string(nil), latestReview.Divergences...), req.Divergences...))
	summaryText := firstNonEmpty(strings.TrimSpace(req.Summary), fmt.Sprintf("Escalate disputed imported reciprocal appeal-board ruling %s into governed rehearing", summary.CounterpartyReviewAppealID))
	description := firstNonEmpty(strings.TrimSpace(req.Description), "The local organization escalated the disputed imported reciprocal appeal-board ruling into a fresh signed rehearing generation.")
	reason := firstNonEmpty(strings.TrimSpace(req.Reason), "escalate disputed imported reciprocal appeal-board ruling into rehearing")
	metadata := mergeStringMaps(req.Metadata, map[string]string{
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_escalated":                    "true",
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_snapshot_id":                  summary.SnapshotID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_bundle_id":                    summary.BundleID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_id":                                  summary.CounterpartyReviewID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_id":                           summary.CounterpartyReviewAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_transition_id":                latestReview.TransitionID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_reference":       firstNonEmpty(strings.TrimSpace(req.CounterpartyReference), strings.TrimSpace(latestReview.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_reference"])),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_status":                string(latestReview.ReviewStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_action":                string(latestReview.Action),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_divergences":                  strings.Join(divergences, ","),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_board_response_appeal_id":     localBoardAppeal.ResponseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_board_response_appeal_status": string(localBoardAppeal.Status),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_board_response_status":        string(localBoardAppeal.ResponseStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_board_response_action":        string(localBoardAppeal.ResponseAction),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_board_response_transition_id": localBoardAppeal.ResponseTransitionID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_board_ruling":                 string(localBoardAppeal.Ruling),
	})
	return s.RehearFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeal(ctx, cellID, localBoardResponseAppealID, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehearingRequest{
		ActorDID:                            req.ActorDID,
		AppealingParty:                      req.AppealingParty,
		CorrectionBoardParty:                req.CorrectionBoardParty,
		EnforcementAcknowledgementParty:     req.EnforcementAcknowledgementParty,
		Summary:                             summaryText,
		Description:                         description,
		EvidenceIDs:                         uniqueTrimmedStrings(append(append([]string(nil), req.EvidenceIDs...), summary.SnapshotID, summary.CounterpartyReviewAppealID, localBoardResponseAppealID)),
		CorrectionBoardReviewThreshold:      req.CorrectionBoardReviewThreshold,
		EligibleCorrectionBoardReviewerDIDs: append([]string(nil), req.EligibleCorrectionBoardReviewerDIDs...),
		Reason:                              reason,
		Metadata:                            metadata,
	})
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewFilter(record, filter) {
				continue
			}
			items = append(items, record)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		iPriority := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionPriority(items[i].Action)
		jPriority := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionPriority(items[j].Action)
		if iPriority != jPriority {
			return iPriority > jPriority
		}
		if items[i].OccurredAt.Equal(items[j].OccurredAt) {
			return items[i].TransitionID > items[j].TransitionID
		}
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAction(ctx context.Context, cellID string, spec secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionSpec) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, err := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummaryBySnapshot(run, strings.TrimSpace(spec.snapshotID))
	if err != nil {
		return nil, err
	}
	localAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, summary.ResponseAppealID)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(spec.actorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: %w: actor %q is not permitted to review imported reciprocal appeal-board ruling %q", ErrPolicyDenied, actorDID, summary.SnapshotID)
	}

	alignmentStatus, divergenceCount := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAlignmentForLocalAndCounterpartyBoard(*localAppeal, summary)
	divergences := uniqueTrimmedStrings(spec.divergences)
	if spec.action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionDispute && len(divergences) == 0 {
		divergences = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDivergences(*localAppeal, summary)
	}
	latestReview := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAction(run, summary.SnapshotID)
	if latestReview != nil && latestReview.ReviewStatus == spec.reviewStatus {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: reciprocal appeal-board snapshot %q is already %s", summary.SnapshotID, spec.reviewStatus)
	}

	receipt, err := s.evaluateStage(ctx, run.request, spec.stage, lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                        summary.OrganizationID,
		"federation_incident_id":                                                            summary.IncidentID,
		"federation_incident_response_id":                                                   summary.ResponseID,
		"federation_incident_directive_id":                                                  summary.DirectiveID,
		"federation_incident_directive_extension_id":                                        summary.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                summary.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                 summary.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":        summary.ChallengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id": summary.ChallengeAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":                                                                   summary.ResponseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_snapshot_id":                               summary.SnapshotID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_bundle_id":                                 summary.BundleID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_id":                                        strings.TrimSpace(summary.CounterpartyReviewAppealID),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_status":                                    string(summary.Status),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_status":                             string(spec.reviewStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_action":                             string(spec.action),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_board_response_appeal_id":     summary.CounterpartyBoardResponseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_board_response_appeal_status": string(summary.CounterpartyBoardResponseAppealStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_board_ruling":                 string(summary.CounterpartyBoardRuling),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_alignment_status":                          string(alignmentStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_alignment_count":                           fmt.Sprintf("%d", divergenceCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_divergences":                               strings.Join(divergences, ","),
		"transition_reason": strings.TrimSpace(spec.reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewTransitionSuffix(spec.action), summary.SnapshotID),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewTransitionSuffix(spec.action),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal",
		TargetDID:        summary.SnapshotID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(spec.reason),
		Metadata: mergeStringMaps(spec.metadata, map[string]string{
			"federation_organization_id":                                                        summary.OrganizationID,
			"federation_sponsor_of_record":                                                      summary.SponsorOfRecord,
			"federation_organization_name":                                                      summary.OrganizationName,
			"federation_incident_id":                                                            summary.IncidentID,
			"federation_incident_response_id":                                                   summary.ResponseID,
			"federation_incident_directive_id":                                                  summary.DirectiveID,
			"federation_incident_directive_extension_id":                                        summary.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                summary.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                 summary.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":        summary.ChallengeID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id": summary.ChallengeAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":                                                                   summary.ResponseAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status":                                                               string(summary.ResponseAppealStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_status":                                                                      string(summary.ResponseStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_action":                                                                      string(summary.ResponseAction),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_transition_id":                                                               summary.ResponseTransitionID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_ruling":                                                                      string(summary.LocalRuling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_snapshot_id":                               summary.SnapshotID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_bundle_id":                                 summary.BundleID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_id":                                               summary.CounterpartyReviewID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_id":                                        summary.CounterpartyReviewAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_status":                                    string(summary.Status),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_status":                             string(spec.reviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_review_action":                             string(spec.action),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_reference":                    strings.TrimSpace(spec.counterpartyReference),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_board_response_appeal_id":     summary.CounterpartyBoardResponseAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_board_response_appeal_status": string(summary.CounterpartyBoardResponseAppealStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_board_response_status":        string(summary.CounterpartyBoardResponseStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_board_response_action":        string(summary.CounterpartyBoardResponseAction),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_board_response_transition_id": summary.CounterpartyBoardResponseTransitionID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_counterparty_board_ruling":                 string(summary.CounterpartyBoardRuling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_alignment_status":                          string(alignmentStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_alignment_count":                           fmt.Sprintf("%d", divergenceCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_divergences":                               strings.Join(divergences, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellValidateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSemantics(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle, organizationID string) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: bundle is required")
	}
	if strings.TrimSpace(bundle.Organization.OrganizationID) != "" && !strings.EqualFold(strings.TrimSpace(bundle.Organization.OrganizationID), strings.TrimSpace(organizationID)) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: bundle organization %q does not match federation organization %q", bundle.Organization.OrganizationID, organizationID)
	}
	if strings.TrimSpace(bundle.ReviewAppeal.OrganizationID) != "" && !strings.EqualFold(strings.TrimSpace(bundle.ReviewAppeal.OrganizationID), strings.TrimSpace(organizationID)) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: review appeal organization %q does not match federation organization %q", bundle.ReviewAppeal.OrganizationID, organizationID)
	}
	if strings.TrimSpace(bundle.ReviewAppeal.AppealReviewID) == "" || strings.TrimSpace(bundle.Review.ReviewID) == "" || strings.TrimSpace(bundle.CounterpartyAppeal.ResponseAppealID) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: bundle review lineage is incomplete")
	}
	if bundle.LocalBoardResponseAppeal == nil || strings.TrimSpace(bundle.LocalBoardResponseAppeal.ResponseAppealID) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: local board response appeal is required")
	}
	if strings.TrimSpace(bundle.ReviewAppeal.CounterpartyResponseAppealID) != "" && !strings.EqualFold(strings.TrimSpace(bundle.ReviewAppeal.CounterpartyResponseAppealID), strings.TrimSpace(bundle.CounterpartyAppeal.ResponseAppealID)) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: review appeal counterparty response appeal %q does not match imported appeal %q", bundle.ReviewAppeal.CounterpartyResponseAppealID, bundle.CounterpartyAppeal.ResponseAppealID)
	}
	if strings.TrimSpace(bundle.ReviewAppeal.BoardResponseAppealID) != "" && !strings.EqualFold(strings.TrimSpace(bundle.ReviewAppeal.BoardResponseAppealID), strings.TrimSpace(bundle.LocalBoardResponseAppeal.ResponseAppealID)) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: review appeal board response appeal %q does not match bundled board appeal %q", bundle.ReviewAppeal.BoardResponseAppealID, bundle.LocalBoardResponseAppeal.ResponseAppealID)
	}
	return nil
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleStatusAt(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle, verificationErr error, now time.Time) (SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus, string, bool) {
	if verificationErr != nil {
		return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatusInvalid, verificationErr.Error(), false
	}
	if bundle != nil && bundle.ExpiresAt != nil {
		if bundle.ExpiresAt.Before(now) {
			return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatusExpired, "bundle has expired", false
		}
		if bundle.ExpiresAt.Before(now.Add(24 * time.Hour)) {
			return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatusStale, "bundle is nearing expiry", true
		}
	}
	return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatusVerified, "", true
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummaryFromSnapshot(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSnapshot) SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary {
	orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(snapshot.OrganizationID))
	reviewStatus, lastReviewedBy, lastReviewedAt, reviewActionCount := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStateForSnapshot(run, strings.TrimSpace(snapshot.SnapshotID))
	alignmentStatus := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusCounterpartyOnly
	alignmentDivergenceCount := 0
	if localAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ResponseAppealID)); err == nil && localAppeal != nil {
		alignmentStatus, alignmentDivergenceCount = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAlignmentForLocalAndCounterpartyBoard(*localAppeal, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummaryProjected(snapshot, run))
	}
	item := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary{
		CellID:                      safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                    safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                  safeSecureCellStatus(run),
		Jurisdiction:                safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:              strings.TrimSpace(snapshot.OrganizationID),
		SponsorOfRecord:             strings.TrimSpace(orgSummary.SponsorOfRecord),
		OrganizationName:            strings.TrimSpace(orgSummary.OrganizationName),
		SnapshotID:                  strings.TrimSpace(snapshot.SnapshotID),
		BundleID:                    strings.TrimSpace(snapshot.Bundle.ID),
		BundleVersion:               strings.TrimSpace(snapshot.Bundle.Version),
		BundleName:                  strings.TrimSpace(snapshot.Bundle.Name),
		Status:                      snapshot.Status,
		Verified:                    snapshot.Verified,
		Signer:                      strings.TrimSpace(snapshot.Signer),
		IncidentID:                  strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.IncidentID),
		ResponseID:                  strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ResponseID),
		DirectiveID:                 strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.DirectiveID),
		ExtensionID:                 strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ExtensionID),
		DisputeID:                   strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.DisputeID),
		AppealID:                    strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.AppealID),
		ChallengeID:                 strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ChallengeID),
		ChallengeAppealID:           strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ChallengeAppealID),
		ResponseAppealID:            strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ResponseAppealID),
		ResponseAppealStatus:        snapshot.Bundle.CounterpartyAppeal.ResponseAppealStatus,
		ResponseStatus:              snapshot.Bundle.CounterpartyAppeal.ResponseStatus,
		ResponseAction:              snapshot.Bundle.CounterpartyAppeal.ResponseAction,
		ResponseTransitionID:        strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ResponseTransitionID),
		LocalRuling:                 snapshot.Bundle.CounterpartyAppeal.Ruling,
		CounterpartyReviewID:        strings.TrimSpace(snapshot.Bundle.Review.ReviewID),
		CounterpartyReviewAppealID:  strings.TrimSpace(snapshot.Bundle.ReviewAppeal.AppealReviewID),
		CounterpartyReviewStatus:    snapshot.Bundle.Review.ReviewStatus,
		CounterpartyReviewAction:    snapshot.Bundle.Review.LatestReviewAction,
		CounterpartyReviewReference: strings.TrimSpace(snapshot.Bundle.Review.CounterpartyReference),
		AlignmentStatus:             alignmentStatus,
		AlignmentDivergenceCount:    alignmentDivergenceCount,
		ReviewStatus:                reviewStatus,
		LastReviewedBy:              strings.TrimSpace(lastReviewedBy),
		LastReviewedAt:              cloneTimePtr(lastReviewedAt),
		ReviewActionCount:           reviewActionCount,
		GeneratedAt:                 snapshot.Bundle.GeneratedAt.UTC(),
		ExpiresAt:                   cloneTimePtr(snapshot.Bundle.ExpiresAt),
		ReceivedAt:                  snapshot.ReceivedAt.UTC(),
		ControlLedgerID:             strings.TrimSpace(snapshot.Bundle.ControlLedgerID),
		ControlLedgerHash:           strings.TrimSpace(snapshot.Bundle.ControlLedgerHash),
		PortablePackageHash:         strings.TrimSpace(snapshot.Bundle.PortablePackageHash),
		PortablePackageSigned:       snapshot.Bundle.PortablePackageSigned,
		PortablePackageAnchored:     snapshot.Bundle.PortablePackageAnchored,
		VerificationMessage:         strings.TrimSpace(snapshot.VerificationMessage),
	}
	if snapshot.Bundle.LocalBoardResponseAppeal != nil {
		item.CounterpartyBoardResponseAppealID = strings.TrimSpace(snapshot.Bundle.LocalBoardResponseAppeal.ResponseAppealID)
		item.CounterpartyBoardResponseAppealStatus = snapshot.Bundle.LocalBoardResponseAppeal.Status
		item.CounterpartyBoardResponseStatus = snapshot.Bundle.LocalBoardResponseAppeal.ResponseStatus
		item.CounterpartyBoardResponseAction = snapshot.Bundle.LocalBoardResponseAppeal.ResponseAction
		item.CounterpartyBoardResponseTransitionID = strings.TrimSpace(snapshot.Bundle.LocalBoardResponseAppeal.ResponseTransitionID)
		item.CounterpartyBoardRuling = snapshot.Bundle.LocalBoardResponseAppeal.Ruling
	}
	if snapshot.Bundle.Signature != nil {
		item.KeyID = strings.TrimSpace(snapshot.Bundle.Signature.KeyID)
	}
	return item
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummaryBySnapshot(run *secureCellRun, snapshotID string) (SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary, error) {
	for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals {
		if strings.EqualFold(strings.TrimSpace(snapshot.SnapshotID), strings.TrimSpace(snapshotID)) {
			return secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummaryFromSnapshot(run, snapshot), nil
		}
	}
	return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary{}, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal: %w: snapshot %q", ErrFederationIncidentDirectiveNotFound, snapshotID)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStateForSnapshot(run *secureCellRun, snapshotID string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus, string, *time.Time, int) {
	status := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusUnreviewed
	var lastReviewedBy string
	var lastReviewedAt *time.Time
	var lastTransitionID string
	currentPriority := 0
	count := 0
	for _, transition := range run.result.Transitions {
		actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionTypeFromTransition(transition.Action, transition.Metadata)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_snapshot_id"]), strings.TrimSpace(snapshotID)) {
			continue
		}
		at := transition.OccurredAt.UTC()
		count++
		priority := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionPriority(actionType)
		if priority < currentPriority {
			continue
		}
		if priority == currentPriority && lastReviewedAt != nil && (at.Before(*lastReviewedAt) || (at.Equal(*lastReviewedAt) && strings.Compare(strings.TrimSpace(transition.ID), lastTransitionID) <= 0)) {
			continue
		}
		status = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusForAction(actionType)
		lastReviewedBy = strings.TrimSpace(transition.Actor)
		lastReviewedAt = &at
		lastTransitionID = strings.TrimSpace(transition.ID)
		currentPriority = priority
	}
	return status, lastReviewedBy, lastReviewedAt, count
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewAction(run *secureCellRun, snapshotID string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord {
	var latest *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord
	currentPriority := 0
	for _, transition := range run.result.Transitions {
		actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionTypeFromTransition(transition.Action, transition.Metadata)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_snapshot_id"]), strings.TrimSpace(snapshotID)) {
			continue
		}
		recordCopy := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord{
			SnapshotID:   strings.TrimSpace(snapshotID),
			Action:       actionType,
			ReviewStatus: secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusForAction(actionType),
			ActorDID:     strings.TrimSpace(transition.Actor),
			OccurredAt:   transition.OccurredAt.UTC(),
			TransitionID: strings.TrimSpace(transition.ID),
			Metadata:     cloneStringMap(transition.Metadata),
		}
		priority := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionPriority(actionType)
		if priority < currentPriority {
			continue
		}
		if priority == currentPriority && latest != nil && (recordCopy.OccurredAt.Before(latest.OccurredAt) || (recordCopy.OccurredAt.Equal(latest.OccurredAt) && strings.Compare(recordCopy.TransitionID, latest.TransitionID) <= 0)) {
			continue
		}
		latest = &recordCopy
		currentPriority = priority
	}
	return latest
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord, bool) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord{}, false
	}
	meta := transition.Metadata
	actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionTypeFromTransition(transition.Action, transition.Metadata)
	if !ok {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord{}, false
	}
	snapshotID := strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_snapshot_id"])
	if snapshotID == "" {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord{}, false
	}
	var snapshot *SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSnapshot
	for idx := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals {
		candidate := &run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppeals[idx]
		if strings.EqualFold(strings.TrimSpace(candidate.SnapshotID), snapshotID) {
			snapshot = candidate
			break
		}
	}
	if snapshot == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord{}, false
	}
	orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(snapshot.OrganizationID))
	projected := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummaryProjected(*snapshot, run)
	alignmentStatus := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusCounterpartyOnly
	alignmentDivergenceCount := 0
	if localAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ResponseAppealID)); err == nil && localAppeal != nil {
		alignmentStatus, alignmentDivergenceCount = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAlignmentForLocalAndCounterpartyBoard(*localAppeal, projected)
	}
	record := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord{
		CellID:                      safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                    safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                  safeSecureCellStatus(run),
		Jurisdiction:                safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:              strings.TrimSpace(snapshot.OrganizationID),
		SponsorOfRecord:             strings.TrimSpace(orgSummary.SponsorOfRecord),
		OrganizationName:            strings.TrimSpace(orgSummary.OrganizationName),
		IncidentID:                  strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.IncidentID),
		ResponseID:                  strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ResponseID),
		DirectiveID:                 strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.DirectiveID),
		ExtensionID:                 strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ExtensionID),
		DisputeID:                   strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.DisputeID),
		AppealID:                    strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.AppealID),
		ChallengeID:                 strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ChallengeID),
		ChallengeAppealID:           strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ChallengeAppealID),
		ResponseAppealID:            strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ResponseAppealID),
		ResponseAppealStatus:        snapshot.Bundle.CounterpartyAppeal.ResponseAppealStatus,
		ResponseStatus:              snapshot.Bundle.CounterpartyAppeal.ResponseStatus,
		ResponseAction:              snapshot.Bundle.CounterpartyAppeal.ResponseAction,
		ResponseTransitionID:        strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ResponseTransitionID),
		LocalRuling:                 snapshot.Bundle.CounterpartyAppeal.Ruling,
		SnapshotID:                  strings.TrimSpace(snapshot.SnapshotID),
		BundleID:                    strings.TrimSpace(snapshot.Bundle.ID),
		CounterpartyReviewID:        strings.TrimSpace(snapshot.Bundle.Review.ReviewID),
		CounterpartyReviewAppealID:  strings.TrimSpace(snapshot.Bundle.ReviewAppeal.AppealReviewID),
		CounterpartyReviewStatus:    snapshot.Bundle.Review.ReviewStatus,
		CounterpartyReviewAction:    snapshot.Bundle.Review.LatestReviewAction,
		CounterpartyReviewReference: strings.TrimSpace(snapshot.Bundle.Review.CounterpartyReference),
		Status:                      snapshot.Status,
		ReviewStatus:                secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusForAction(actionType),
		Action:                      actionType,
		AlignmentStatus:             SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_alignment_status"])),
		AlignmentDivergenceCount:    secureCellParseOptionalInt(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_alignment_count"]),
		Divergences:                 secureCellSplitAndTrim(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_divergences"], ","),
		TransitionID:                strings.TrimSpace(transition.ID),
		ActorDID:                    strings.TrimSpace(transition.Actor),
		Reason:                      strings.TrimSpace(transition.Reason),
		Metadata:                    cloneStringMap(meta),
		OccurredAt:                  transition.OccurredAt.UTC(),
	}
	if record.AlignmentStatus == "" {
		record.AlignmentStatus = alignmentStatus
	}
	if record.AlignmentDivergenceCount == 0 {
		record.AlignmentDivergenceCount = alignmentDivergenceCount
	}
	if snapshot.Bundle.LocalBoardResponseAppeal != nil {
		record.CounterpartyBoardResponseAppealID = strings.TrimSpace(snapshot.Bundle.LocalBoardResponseAppeal.ResponseAppealID)
		record.CounterpartyBoardResponseAppealStatus = snapshot.Bundle.LocalBoardResponseAppeal.Status
		record.CounterpartyBoardResponseStatus = snapshot.Bundle.LocalBoardResponseAppeal.ResponseStatus
		record.CounterpartyBoardResponseAction = snapshot.Bundle.LocalBoardResponseAppeal.ResponseAction
		record.CounterpartyBoardResponseTransitionID = strings.TrimSpace(snapshot.Bundle.LocalBoardResponseAppeal.ResponseTransitionID)
		record.CounterpartyBoardRuling = snapshot.Bundle.LocalBoardResponseAppeal.Ruling
	}
	if transition.PolicyReceipt != nil {
		record.PolicyReceiptID = strings.TrimSpace(transition.PolicyReceipt.ID)
		record.PolicyReceiptHash = strings.TrimSpace(transition.PolicyReceipt.ContentHash)
	}
	if transition.ExecutionSeal != nil {
		record.SealID = strings.TrimSpace(transition.ExecutionSeal.SealID)
	}
	if transition.TraceLink != nil {
		record.TraceLinkID = strings.TrimSpace(transition.TraceLink.ID)
	}
	return record, true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionTypeFromTransition(action string, meta map[string]string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType, bool) {
	switch strings.TrimSpace(action) {
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_ruling_acknowledged":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionAcknowledge, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_ruling_disputed":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionDispute, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_rehearing_requested":
		if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealEscalationMeta(meta) {
			return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionEscalate, true
		}
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruled":
		if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealEscalationMeta(meta) {
			return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionResolve, true
		}
	default:
		return "", false
	}
	return "", false
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusForAction(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionAcknowledge:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusAcknowledged
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionDispute:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusDisputed
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionEscalate:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusEscalated
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionResolve:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusResolved
	default:
		return ""
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionPriority(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType) int {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionAcknowledge:
		return 1
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionDispute:
		return 2
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionEscalate:
		return 3
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionResolve:
		return 4
	default:
		return 0
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealEscalationMeta(meta map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_escalated"]), "true")
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewTransitionSuffix(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionType) string {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionAcknowledge:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_ruling_acknowledged"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionDispute:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_ruling_disputed"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionEscalate:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_ruling_escalated"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActionResolve:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_ruling_resolved"
	default:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review_appeal_ruling_reviewed"
	}
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealsByStatus(items []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSnapshot, status SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealStatus) []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSnapshot {
	filtered := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSnapshot, 0)
	for _, item := range items {
		if item.Status == status {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummaryProjected(snapshot SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSnapshot, run *secureCellRun) SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary {
	item := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary{
		CellID:                      safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                    safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                  safeSecureCellStatus(run),
		Jurisdiction:                safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:              strings.TrimSpace(snapshot.OrganizationID),
		SnapshotID:                  strings.TrimSpace(snapshot.SnapshotID),
		BundleID:                    strings.TrimSpace(snapshot.Bundle.ID),
		Status:                      snapshot.Status,
		Verified:                    snapshot.Verified,
		IncidentID:                  strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.IncidentID),
		ResponseID:                  strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ResponseID),
		DirectiveID:                 strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.DirectiveID),
		ExtensionID:                 strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ExtensionID),
		DisputeID:                   strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.DisputeID),
		AppealID:                    strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.AppealID),
		ChallengeID:                 strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ChallengeID),
		ChallengeAppealID:           strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ChallengeAppealID),
		ResponseAppealID:            strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ResponseAppealID),
		ResponseAppealStatus:        snapshot.Bundle.CounterpartyAppeal.ResponseAppealStatus,
		ResponseStatus:              snapshot.Bundle.CounterpartyAppeal.ResponseStatus,
		ResponseAction:              snapshot.Bundle.CounterpartyAppeal.ResponseAction,
		ResponseTransitionID:        strings.TrimSpace(snapshot.Bundle.CounterpartyAppeal.ResponseTransitionID),
		LocalRuling:                 snapshot.Bundle.CounterpartyAppeal.Ruling,
		CounterpartyReviewID:        strings.TrimSpace(snapshot.Bundle.Review.ReviewID),
		CounterpartyReviewAppealID:  strings.TrimSpace(snapshot.Bundle.ReviewAppeal.AppealReviewID),
		CounterpartyReviewStatus:    snapshot.Bundle.Review.ReviewStatus,
		CounterpartyReviewAction:    snapshot.Bundle.Review.LatestReviewAction,
		CounterpartyReviewReference: strings.TrimSpace(snapshot.Bundle.Review.CounterpartyReference),
		GeneratedAt:                 snapshot.Bundle.GeneratedAt.UTC(),
		ExpiresAt:                   cloneTimePtr(snapshot.Bundle.ExpiresAt),
		ReceivedAt:                  snapshot.ReceivedAt.UTC(),
		ControlLedgerID:             strings.TrimSpace(snapshot.Bundle.ControlLedgerID),
		ControlLedgerHash:           strings.TrimSpace(snapshot.Bundle.ControlLedgerHash),
		PortablePackageHash:         strings.TrimSpace(snapshot.Bundle.PortablePackageHash),
		PortablePackageSigned:       snapshot.Bundle.PortablePackageSigned,
		PortablePackageAnchored:     snapshot.Bundle.PortablePackageAnchored,
		VerificationMessage:         strings.TrimSpace(snapshot.VerificationMessage),
	}
	if snapshot.Bundle.LocalBoardResponseAppeal != nil {
		item.CounterpartyBoardResponseAppealID = strings.TrimSpace(snapshot.Bundle.LocalBoardResponseAppeal.ResponseAppealID)
		item.CounterpartyBoardResponseAppealStatus = snapshot.Bundle.LocalBoardResponseAppeal.Status
		item.CounterpartyBoardResponseStatus = snapshot.Bundle.LocalBoardResponseAppeal.ResponseStatus
		item.CounterpartyBoardResponseAction = snapshot.Bundle.LocalBoardResponseAppeal.ResponseAction
		item.CounterpartyBoardResponseTransitionID = strings.TrimSpace(snapshot.Bundle.LocalBoardResponseAppeal.ResponseTransitionID)
		item.CounterpartyBoardRuling = snapshot.Bundle.LocalBoardResponseAppeal.Ruling
	}
	if snapshot.Bundle.Signature != nil {
		item.Signer = strings.TrimSpace(snapshot.Signer)
		item.KeyID = strings.TrimSpace(snapshot.Bundle.Signature.KeyID)
	}
	return item
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealAlignmentForLocalAndCounterpartyBoard(local SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, counterparty SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus, int) {
	divergenceCount := 0
	if local.Status != counterparty.CounterpartyBoardResponseAppealStatus {
		divergenceCount++
	}
	if local.ResponseStatus != counterparty.CounterpartyBoardResponseStatus {
		divergenceCount++
	}
	if local.ResponseAction != counterparty.CounterpartyBoardResponseAction {
		divergenceCount++
	}
	if local.Ruling != counterparty.CounterpartyBoardRuling {
		divergenceCount++
	}
	if divergenceCount == 0 {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusAligned, 0
	}
	return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusDivergent, divergenceCount
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealDivergences(local SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, counterparty SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary) []string {
	divergences := make([]string, 0, 4)
	if local.Status != counterparty.CounterpartyBoardResponseAppealStatus {
		divergences = append(divergences, "counterparty appeal-board response appeal status diverged")
	}
	if local.ResponseStatus != counterparty.CounterpartyBoardResponseStatus {
		divergences = append(divergences, "counterparty appeal-board response status diverged")
	}
	if local.ResponseAction != counterparty.CounterpartyBoardResponseAction {
		divergences = append(divergences, "counterparty appeal-board response action diverged")
	}
	if local.Ruling != counterparty.CounterpartyBoardRuling {
		divergences = append(divergences, "counterparty appeal-board ruling diverged from local response appeal ruling")
	}
	if len(divergences) == 0 {
		divergences = append(divergences, "counterparty appeal-board posture diverged from the local response appeal")
	}
	return divergences
}

func matchesSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter(item SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary, filter SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(item.IncidentID), strings.TrimSpace(filter.IncidentID)) {
		return false
	}
	if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(item.ResponseID), strings.TrimSpace(filter.ResponseID)) {
		return false
	}
	if filter.DirectiveID != "" && !strings.EqualFold(strings.TrimSpace(item.DirectiveID), strings.TrimSpace(filter.DirectiveID)) {
		return false
	}
	if filter.ExtensionID != "" && !strings.EqualFold(strings.TrimSpace(item.ExtensionID), strings.TrimSpace(filter.ExtensionID)) {
		return false
	}
	if filter.DisputeID != "" && !strings.EqualFold(strings.TrimSpace(item.DisputeID), strings.TrimSpace(filter.DisputeID)) {
		return false
	}
	if filter.AppealID != "" && !strings.EqualFold(strings.TrimSpace(item.AppealID), strings.TrimSpace(filter.AppealID)) {
		return false
	}
	if filter.ChallengeID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeID), strings.TrimSpace(filter.ChallengeID)) {
		return false
	}
	if filter.ChallengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeAppealID), strings.TrimSpace(filter.ChallengeAppealID)) {
		return false
	}
	if filter.ResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ResponseAppealID), strings.TrimSpace(filter.ResponseAppealID)) {
		return false
	}
	if filter.SnapshotID != "" && !strings.EqualFold(strings.TrimSpace(item.SnapshotID), strings.TrimSpace(filter.SnapshotID)) {
		return false
	}
	if filter.CounterpartyReviewID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartyReviewID), strings.TrimSpace(filter.CounterpartyReviewID)) {
		return false
	}
	if filter.CounterpartyReviewAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartyReviewAppealID), strings.TrimSpace(filter.CounterpartyReviewAppealID)) {
		return false
	}
	if filter.CounterpartyBoardResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartyBoardResponseAppealID), strings.TrimSpace(filter.CounterpartyBoardResponseAppealID)) {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.ReviewStatus != "" && item.ReviewStatus != filter.ReviewStatus {
		return false
	}
	return true
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(item.IncidentID), strings.TrimSpace(filter.IncidentID)) {
		return false
	}
	if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(item.ResponseID), strings.TrimSpace(filter.ResponseID)) {
		return false
	}
	if filter.DirectiveID != "" && !strings.EqualFold(strings.TrimSpace(item.DirectiveID), strings.TrimSpace(filter.DirectiveID)) {
		return false
	}
	if filter.ExtensionID != "" && !strings.EqualFold(strings.TrimSpace(item.ExtensionID), strings.TrimSpace(filter.ExtensionID)) {
		return false
	}
	if filter.DisputeID != "" && !strings.EqualFold(strings.TrimSpace(item.DisputeID), strings.TrimSpace(filter.DisputeID)) {
		return false
	}
	if filter.AppealID != "" && !strings.EqualFold(strings.TrimSpace(item.AppealID), strings.TrimSpace(filter.AppealID)) {
		return false
	}
	if filter.ChallengeID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeID), strings.TrimSpace(filter.ChallengeID)) {
		return false
	}
	if filter.ChallengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeAppealID), strings.TrimSpace(filter.ChallengeAppealID)) {
		return false
	}
	if filter.ResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ResponseAppealID), strings.TrimSpace(filter.ResponseAppealID)) {
		return false
	}
	if filter.SnapshotID != "" && !strings.EqualFold(strings.TrimSpace(item.SnapshotID), strings.TrimSpace(filter.SnapshotID)) {
		return false
	}
	if filter.CounterpartyReviewAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartyReviewAppealID), strings.TrimSpace(filter.CounterpartyReviewAppealID)) {
		return false
	}
	if filter.CounterpartyBoardResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartyBoardResponseAppealID), strings.TrimSpace(filter.CounterpartyBoardResponseAppealID)) {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.ReviewStatus != "" && item.ReviewStatus != filter.ReviewStatus {
		return false
	}
	if filter.Action != "" && item.Action != filter.Action {
		return false
	}
	if filter.ActorDID != "" && !strings.EqualFold(strings.TrimSpace(item.ActorDID), strings.TrimSpace(filter.ActorDID)) {
		return false
	}
	return true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundleSignerName(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle) string {
	if bundle == nil || bundle.Signature == nil {
		return ""
	}
	return strings.TrimSpace(bundle.Signature.Signer)
}

func secureCellCloneFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(in SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle {
	data, _ := json.Marshal(in)
	var out SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle
	_ = json.Unmarshal(data, &out)
	return out
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatusCount(items []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary, status SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewStatus) int {
	count := 0
	for _, item := range items {
		if item.ReviewStatus == status {
			count++
		}
	}
	return count
}

func secureCellParseOptionalInt(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0
	}
	return value
}

func secureCellSplitAndTrim(raw string, sep string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, sep)
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			items = append(items, part)
		}
	}
	return items
}
