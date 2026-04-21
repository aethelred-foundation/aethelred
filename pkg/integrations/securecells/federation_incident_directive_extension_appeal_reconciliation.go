package securecells

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

const secureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus
// tracks the latest governed review posture over one bilateral appeal
// reconciliation key.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusUnreviewed   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus = "unreviewed"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusAcknowledged SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus = "acknowledged"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus = "disputed"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusResolved     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus = "resolved"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionType
// captures one governed operator action over a bilateral appeal reconciliation.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionType string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionAcknowledge SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionType = "acknowledge"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionDispute     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionType = "dispute"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionResolve     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionType = "resolve"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAcknowledgeRequest
// marks one bilateral appeal reconciliation as reviewed and accepted.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAcknowledgeRequest struct {
	ActorDID string            `json:"actor_did,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationDisputeRequest
// records one challenge against imported or mismatched counterparty appeal
// posture.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationDisputeRequest struct {
	ActorDID    string            `json:"actor_did,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Divergences []string          `json:"divergences,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolveRequest
// records one bilateral decision that the disputed appeal posture has been
// resolved.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolveRequest struct {
	ActorDID string            `json:"actor_did,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFilter
// narrows operator views across governed appeal-reconciliation reviews.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFilter struct {
	CellID         string                                                                         `json:"cell_id,omitempty"`
	OrganizationID string                                                                         `json:"organization_id,omitempty"`
	IncidentID     string                                                                         `json:"incident_id,omitempty"`
	ResponseID     string                                                                         `json:"response_id,omitempty"`
	DirectiveID    string                                                                         `json:"directive_id,omitempty"`
	ExtensionID    string                                                                         `json:"extension_id,omitempty"`
	DisputeID      string                                                                         `json:"dispute_id,omitempty"`
	AppealID       string                                                                         `json:"appeal_id,omitempty"`
	ComparisonKey  string                                                                         `json:"comparison_key,omitempty"`
	Action         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionType   `json:"action,omitempty"`
	ReviewStatus   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus `json:"review_status,omitempty"`
	ActorDID       string                                                                         `json:"actor_did,omitempty"`
	Limit          int                                                                            `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord
// is the operator-facing evidence record for one governed appeal-reconciliation
// action.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord struct {
	CellID                 string                                                                         `json:"cell_id"`
	CellName               string                                                                         `json:"cell_name,omitempty"`
	CellStatus             SecureCellStatus                                                               `json:"cell_status"`
	Jurisdiction           string                                                                         `json:"jurisdiction,omitempty"`
	OrganizationID         string                                                                         `json:"organization_id"`
	SponsorOfRecord        string                                                                         `json:"sponsor_of_record,omitempty"`
	OrganizationName       string                                                                         `json:"organization_name,omitempty"`
	ComparisonKey          string                                                                         `json:"comparison_key"`
	IncidentID             string                                                                         `json:"incident_id,omitempty"`
	ResponseID             string                                                                         `json:"response_id,omitempty"`
	DirectiveID            string                                                                         `json:"directive_id,omitempty"`
	ExtensionID            string                                                                         `json:"extension_id,omitempty"`
	DisputeID              string                                                                         `json:"dispute_id,omitempty"`
	AppealID               string                                                                         `json:"appeal_id,omitempty"`
	LocalAppealID          string                                                                         `json:"local_appeal_id,omitempty"`
	CounterpartySnapshotID string                                                                         `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyBundleID   string                                                                         `json:"counterparty_bundle_id,omitempty"`
	CounterpartyAppealID   string                                                                         `json:"counterparty_appeal_id,omitempty"`
	ReconciliationStatus   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus       `json:"reconciliation_status"`
	ReviewStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus `json:"review_status"`
	Action                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionType   `json:"action"`
	TransitionID           string                                                                         `json:"transition_id,omitempty"`
	PolicyReceiptID        string                                                                         `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash      string                                                                         `json:"policy_receipt_hash,omitempty"`
	SealID                 string                                                                         `json:"seal_id,omitempty"`
	TraceLinkID            string                                                                         `json:"trace_link_id,omitempty"`
	ActorDID               string                                                                         `json:"actor_did,omitempty"`
	Reason                 string                                                                         `json:"reason,omitempty"`
	Divergences            []string                                                                       `json:"divergences,omitempty"`
	Metadata               map[string]string                                                              `json:"metadata,omitempty"`
	OccurredAt             time.Time                                                                      `json:"occurred_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleSignature
// captures detached signer metadata for one reconciliation evidence bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle is
// the signed auditor-facing package for one bilateral appeal reconciliation.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle struct {
	ID                      string                                                                                            `json:"id"`
	Version                 string                                                                                            `json:"version"`
	Name                    string                                                                                            `json:"name"`
	GeneratedAt             time.Time                                                                                         `json:"generated_at"`
	ExpiresAt               *time.Time                                                                                        `json:"expires_at,omitempty"`
	CellID                  string                                                                                            `json:"cell_id"`
	CellName                string                                                                                            `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                                                                                  `json:"cell_status"`
	Jurisdiction            string                                                                                            `json:"jurisdiction,omitempty"`
	Framework               string                                                                                            `json:"framework,omitempty"`
	Organization            SecureCellFederationOrganizationSummary                                                           `json:"organization"`
	Reconciliation          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary                         `json:"reconciliation"`
	LocalAppeal             *SecureCellFederationIncidentDirectiveExtensionAppealSummary                                      `json:"local_appeal,omitempty"`
	CounterpartyAppeal      *SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummary                          `json:"counterparty_appeal,omitempty"`
	Actions                 []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord                  `json:"actions,omitempty"`
	Attestations            []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord `json:"attestations,omitempty"`
	Challenges              []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary              `json:"challenges,omitempty"`
	ChallengeActions        []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord         `json:"challenge_actions,omitempty"`
	AutomationActions       []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionRecord        `json:"automation_actions,omitempty"`
	Contracts               []SecureCellFederationContractSummary                                                             `json:"contracts,omitempty"`
	Controls                []SecureCellFederationTrustPackControl                                                            `json:"controls,omitempty"`
	OperatorSurfaces        []SecureCellFederationOperatorSurface                                                             `json:"operator_surfaces,omitempty"`
	ControlLedgerID         string                                                                                            `json:"control_ledger_id,omitempty"`
	ControlLedgerHash       string                                                                                            `json:"control_ledger_hash,omitempty"`
	PortablePackageHash     string                                                                                            `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                                                                              `json:"portable_package_signed"`
	PortablePackageAnchored bool                                                                                              `json:"portable_package_anchored"`
	ContentHash             string                                                                                            `json:"content_hash,omitempty"`
	Signature               *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleSignature                `json:"signature,omitempty"`
	Metadata                map[string]string                                                                                 `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleOptions
// lets callers tune bundle identity, expiry, and operator-surface hints.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

func (s *Service) AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliation(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAcknowledgeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationAction(ctx, cellID, comparisonKey, secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionSpec{
		stage:    "acknowledge_federation_incident_directive_extension_appeal_reconciliation",
		action:   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionAcknowledge,
		review:   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusAcknowledged,
		actorDID: req.ActorDID,
		reason:   req.Reason,
		metadata: req.Metadata,
	})
}

func (s *Service) DisputeFederationIncidentDirectiveExtensionAppealReconciliation(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationDisputeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationAction(ctx, cellID, comparisonKey, secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionSpec{
		stage:       "dispute_federation_incident_directive_extension_appeal_reconciliation",
		action:      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionDispute,
		review:      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed,
		actorDID:    req.ActorDID,
		reason:      req.Reason,
		metadata:    req.Metadata,
		divergences: req.Divergences,
	})
}

func (s *Service) ResolveFederationIncidentDirectiveExtensionAppealReconciliation(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationResolveRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationAction(ctx, cellID, comparisonKey, secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionSpec{
		stage:    "resolve_federation_incident_directive_extension_appeal_reconciliation",
		action:   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionResolve,
		review:   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusResolved,
		actorDID: req.ActorDID,
		reason:   req.Reason,
		metadata: req.Metadata,
	})
}

func (s *Service) BuildFederationIncidentDirectiveExtensionAppealReconciliationBundle(ctx context.Context, cellID string, comparisonKey string, options SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleOptions) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	reconciliation, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationSummaryByKey(run, comparisonKey)
	if err != nil {
		return nil, err
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, reconciliation.OrganizationID)
	if err != nil {
		return nil, err
	}

	var localAppeal *SecureCellFederationIncidentDirectiveExtensionAppealSummary
	if ref := secureCellLatestLocalFederationIncidentDirectiveExtensionAppealsByKey(run)[reconciliation.ComparisonKey]; ref != nil && ref.Response != nil && ref.Directive != nil && ref.Extension != nil && ref.Dispute != nil && ref.Appeal != nil {
		summary := secureCellFederationIncidentDirectiveExtensionAppealSummaryFromRun(run, *ref.Response, *ref.Directive, *ref.Extension, *ref.Dispute, *ref.Appeal)
		localAppeal = &summary
	}

	var counterpartyAppeal *SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummary
	if snapshot := secureCellLatestCounterpartyFederationIncidentDirectiveExtensionAppealsByKey(run)[reconciliation.ComparisonKey]; snapshot != nil {
		summary := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealSummaryFromRun(run, *snapshot)
		counterpartyAppeal = &summary
	}

	actions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFilter{
		CellID:        cellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		return nil, err
	}
	attestations, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestations(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationFilter{
		CellID:        cellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		return nil, err
	}
	challenges := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary, 0)
	for _, challenge := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengesFromRun(run) {
		if strings.EqualFold(strings.TrimSpace(challenge.ComparisonKey), strings.TrimSpace(comparisonKey)) {
			challenges = append(challenges, challenge)
		}
	}
	challengeActions := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionsForComparisonKey(run, comparisonKey)
	automationActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionFilter{
		CellID:        cellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	bundle := &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle{
		ID:                 firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%x-incident-directive-extension-appeal-reconciliation-bundle", run.result.CellID, sha256.Sum256([]byte(reconciliation.ComparisonKey)))),
		Version:            firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:               firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Incident Directive Extension Appeal Reconciliation Bundle %s", reconciliation.AppealID)),
		GeneratedAt:        now,
		ExpiresAt:          cloneTimePtr(&expiresAt),
		CellID:             run.result.CellID,
		CellName:           run.result.Name,
		CellStatus:         run.result.Status,
		Jurisdiction:       run.request.Jurisdiction,
		Framework:          firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:       orgSummary,
		Reconciliation:     reconciliation,
		LocalAppeal:        localAppeal,
		CounterpartyAppeal: counterpartyAppeal,
		Actions:            append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord(nil), actions...),
		Attestations:       append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationRecord(nil), attestations...),
		Challenges:         append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary(nil), challenges...),
		ChallengeActions:   append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord(nil), challengeActions...),
		AutomationActions:  append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionRecord(nil), automationActions...),
		Contracts:          secureCellFederationContractSummariesForOrganization(run, reconciliation.OrganizationID),
		Controls:           secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces:   cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:           cloneStringMap(options.Metadata),
	}
	if run.result.ControlLedger != nil && run.result.ControlLedger.Bundle != nil {
		bundle.ControlLedgerID = strings.TrimSpace(run.result.ControlLedger.Bundle.ID)
		bundle.ControlLedgerHash = strings.TrimSpace(run.result.ControlLedger.Bundle.ContentHash)
	}
	if run.result.PortablePackage != nil {
		bundle.PortablePackageHash = strings.TrimSpace(run.result.PortablePackage.PackageHash)
		bundle.PortablePackageSigned = run.result.PortablePackage.Signature != nil
		bundle.PortablePackageAnchored = run.result.PortablePackage.AuditAnchor != nil
	}
	if s.config.FederationIncidentDirectiveExtensionAppealReconciliationBundleSigner != nil {
		if err := s.config.FederationIncidentDirectiveExtensionAppealReconciliationBundleSigner(ctx, bundle); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: external bundle signing failed: %w", err)
		}
	} else if err := SignFederationIncidentDirectiveExtensionAppealReconciliationBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFilter(record, filter) {
				continue
			}
			items = append(items, record)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
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

func VerifyFederationIncidentDirectiveExtensionAppealReconciliationBundle(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: bundle is required")
	}
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: signature verification failed")
	}
	return nil
}

func SignFederationIncidentDirectiveExtensionAppealReconciliationBundleEd25519(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleDigest(bundle)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])

	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleSignature{
		Algorithm: secureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleSignatureAlgorithmED25519,
		Signer:    strings.TrimSpace(signer),
		KeyID:     fmt.Sprintf("ed25519:%x", sha256.Sum256(publicKey)),
		Signature: hex.EncodeToString(signature),
		SignedAt:  now,
	}
	if includeVerificationKeys {
		bundle.Signature.PublicKey = hex.EncodeToString(publicKey)
	}
	return nil
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionSpec struct {
	stage       string
	action      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionType
	review      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus
	actorDID    string
	reason      string
	metadata    map[string]string
	divergences []string
}

func (s *Service) applyFederationIncidentDirectiveExtensionAppealReconciliationAction(ctx context.Context, cellID string, comparisonKey string, spec secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionSpec) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationSummaryByKey(run, comparisonKey)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(spec.actorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: %w: actor %q is not permitted to review reconciliation %q", ErrPolicyDenied, actorDID, comparisonKey)
	}
	latest := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationAction(run, summary.ComparisonKey)
	switch spec.action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionAcknowledge:
		if summary.Status != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusAligned {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: only aligned reconciliations can be acknowledged")
		}
		if latest != nil && latest.ReviewStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusAcknowledged {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: reconciliation %q is already acknowledged", summary.ComparisonKey)
		}
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionDispute:
		if strings.TrimSpace(summary.CounterpartySnapshotID) == "" {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: counterparty appeal evidence is required to dispute reconciliation %q", summary.ComparisonKey)
		}
		if latest != nil && latest.ReviewStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: reconciliation %q is already disputed", summary.ComparisonKey)
		}
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionResolve:
		if latest == nil || latest.ReviewStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: reconciliation %q must be disputed before it can be resolved", summary.ComparisonKey)
		}
	default:
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: unsupported action %q", spec.action)
	}

	divergences := uniqueTrimmedStrings(spec.divergences)
	if len(divergences) == 0 && spec.action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionDispute {
		divergences = append(divergences, summary.Divergences...)
	}

	receipt, err := s.evaluateStage(ctx, run.request, spec.stage, lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                summary.OrganizationID,
		"federation_incident_id":                                                    summary.IncidentID,
		"federation_incident_response_id":                                           summary.ResponseID,
		"federation_incident_directive_id":                                          summary.DirectiveID,
		"federation_incident_directive_extension_id":                                summary.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                        summary.DisputeID,
		"federation_incident_directive_extension_appeal_id":                         summary.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_key":         summary.ComparisonKey,
		"federation_incident_directive_extension_appeal_reconciliation_status":      string(summary.Status),
		"federation_incident_directive_extension_appeal_reconciliation_review":      string(spec.review),
		"federation_incident_directive_extension_appeal_reconciliation_action":      string(spec.action),
		"federation_incident_directive_extension_appeal_reconciliation_divergences": strings.Join(divergences, ","),
		"federation_incident_directive_extension_local_appeal_id":                   summary.LocalAppealID,
		"federation_counterparty_incident_directive_extension_appeal_snapshot_id":   summary.CounterpartySnapshotID,
		"federation_counterparty_incident_directive_extension_appeal_bundle_id":     summary.CounterpartyBundleID,
		"federation_counterparty_incident_directive_extension_appeal_id":            summary.CounterpartyAppealID,
		"transition_reason": strings.TrimSpace(spec.reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationTransitionSuffix(spec.action), summary.ComparisonKey),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationTransitionSuffix(spec.action),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation",
		TargetDID:        summary.ComparisonKey,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(spec.reason),
		Metadata: mergeStringMaps(spec.metadata, map[string]string{
			"federation_organization_id":                                                summary.OrganizationID,
			"federation_sponsor_of_record":                                              summary.SponsorOfRecord,
			"federation_organization_name":                                              summary.OrganizationName,
			"federation_incident_id":                                                    summary.IncidentID,
			"federation_incident_response_id":                                           summary.ResponseID,
			"federation_incident_directive_id":                                          summary.DirectiveID,
			"federation_incident_directive_extension_id":                                summary.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                        summary.DisputeID,
			"federation_incident_directive_extension_appeal_id":                         summary.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_key":         summary.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_status":      string(summary.Status),
			"federation_incident_directive_extension_appeal_reconciliation_review":      string(spec.review),
			"federation_incident_directive_extension_appeal_reconciliation_action":      string(spec.action),
			"federation_incident_directive_extension_appeal_reconciliation_divergences": strings.Join(divergences, ","),
			"federation_incident_directive_extension_local_appeal_id":                   summary.LocalAppealID,
			"federation_counterparty_incident_directive_extension_appeal_snapshot_id":   summary.CounterpartySnapshotID,
			"federation_counterparty_incident_directive_extension_appeal_bundle_id":     summary.CounterpartyBundleID,
			"federation_counterparty_incident_directive_extension_appeal_id":            summary.CounterpartyAppealID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationSummaryByKey(run *secureCellRun, comparisonKey string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary, error) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary{}, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: secure cell result is required")
	}
	comparisonKey = strings.TrimSpace(comparisonKey)
	if comparisonKey == "" {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary{}, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: comparison key is required")
	}
	for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationsFromRun(run) {
		if strings.EqualFold(item.ComparisonKey, comparisonKey) {
			return item, nil
		}
	}
	return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary{}, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation: reconciliation %q not found", comparisonKey)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord, bool) {
	actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionTypeFromTransitionAction(transition.Action)
	if !ok {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord{}, false
	}
	meta := cloneStringMap(transition.Metadata)
	record := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord{
		CellID:                 safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:               safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:             safeSecureCellStatus(run),
		Jurisdiction:           safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:         strings.TrimSpace(meta["federation_organization_id"]),
		SponsorOfRecord:        strings.TrimSpace(meta["federation_sponsor_of_record"]),
		OrganizationName:       strings.TrimSpace(meta["federation_organization_name"]),
		ComparisonKey:          strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_key"]),
		IncidentID:             strings.TrimSpace(meta["federation_incident_id"]),
		ResponseID:             strings.TrimSpace(meta["federation_incident_response_id"]),
		DirectiveID:            strings.TrimSpace(meta["federation_incident_directive_id"]),
		ExtensionID:            strings.TrimSpace(meta["federation_incident_directive_extension_id"]),
		DisputeID:              strings.TrimSpace(meta["federation_incident_directive_extension_dispute_id"]),
		AppealID:               strings.TrimSpace(meta["federation_incident_directive_extension_appeal_id"]),
		LocalAppealID:          strings.TrimSpace(meta["federation_incident_directive_extension_local_appeal_id"]),
		CounterpartySnapshotID: strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_snapshot_id"]),
		CounterpartyBundleID:   strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_bundle_id"]),
		CounterpartyAppealID:   strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_id"]),
		ReconciliationStatus:   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_status"])),
		ReviewStatus:           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_review"])),
		Action:                 actionType,
		TransitionID:           strings.TrimSpace(transition.ID),
		ActorDID:               strings.TrimSpace(transition.Actor),
		Reason:                 firstNonEmpty(strings.TrimSpace(transition.Reason), strings.TrimSpace(meta["transition_reason"])),
		Divergences:            uniqueTrimmedStrings(strings.Split(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_divergences"]), ",")),
		Metadata:               meta,
		OccurredAt:             transition.OccurredAt.UTC(),
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
	if record.ReconciliationStatus == "" && record.ComparisonKey != "" {
		if summary, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationSummaryByKey(run, record.ComparisonKey); err == nil {
			record.ReconciliationStatus = summary.Status
			record.OrganizationName = firstNonEmpty(record.OrganizationName, summary.OrganizationName)
			record.SponsorOfRecord = firstNonEmpty(record.SponsorOfRecord, summary.SponsorOfRecord)
			record.IncidentID = firstNonEmpty(record.IncidentID, summary.IncidentID)
			record.ResponseID = firstNonEmpty(record.ResponseID, summary.ResponseID)
			record.DirectiveID = firstNonEmpty(record.DirectiveID, summary.DirectiveID)
			record.ExtensionID = firstNonEmpty(record.ExtensionID, summary.ExtensionID)
			record.DisputeID = firstNonEmpty(record.DisputeID, summary.DisputeID)
			record.AppealID = firstNonEmpty(record.AppealID, summary.AppealID)
			record.LocalAppealID = firstNonEmpty(record.LocalAppealID, summary.LocalAppealID)
			record.CounterpartySnapshotID = firstNonEmpty(record.CounterpartySnapshotID, summary.CounterpartySnapshotID)
			record.CounterpartyBundleID = firstNonEmpty(record.CounterpartyBundleID, summary.CounterpartyBundleID)
			record.CounterpartyAppealID = firstNonEmpty(record.CounterpartyAppealID, summary.CounterpartyAppealID)
			if len(record.Divergences) == 0 {
				record.Divergences = append([]string(nil), summary.Divergences...)
			}
		}
	}
	if record.ReviewStatus == "" {
		record.ReviewStatus = secureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusFromActionType(actionType)
	}
	return record, true
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(item.OrganizationID, strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.IncidentID != "" && !strings.EqualFold(item.IncidentID, strings.TrimSpace(filter.IncidentID)) {
		return false
	}
	if filter.ResponseID != "" && !strings.EqualFold(item.ResponseID, strings.TrimSpace(filter.ResponseID)) {
		return false
	}
	if filter.DirectiveID != "" && !strings.EqualFold(item.DirectiveID, strings.TrimSpace(filter.DirectiveID)) {
		return false
	}
	if filter.ExtensionID != "" && !strings.EqualFold(item.ExtensionID, strings.TrimSpace(filter.ExtensionID)) {
		return false
	}
	if filter.DisputeID != "" && !strings.EqualFold(item.DisputeID, strings.TrimSpace(filter.DisputeID)) {
		return false
	}
	if filter.AppealID != "" && !strings.EqualFold(item.AppealID, strings.TrimSpace(filter.AppealID)) {
		return false
	}
	if filter.ComparisonKey != "" && !strings.EqualFold(item.ComparisonKey, strings.TrimSpace(filter.ComparisonKey)) {
		return false
	}
	if filter.Action != "" && item.Action != filter.Action {
		return false
	}
	if filter.ReviewStatus != "" && item.ReviewStatus != filter.ReviewStatus {
		return false
	}
	if filter.ActorDID != "" && !strings.EqualFold(item.ActorDID, strings.TrimSpace(filter.ActorDID)) {
		return false
	}
	return true
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationAction(run *secureCellRun, comparisonKey string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord {
	if run == nil || run.result == nil {
		return nil
	}
	comparisonKey = strings.TrimSpace(comparisonKey)
	var latest *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionRecord
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFromTransition(run, transition)
		if !ok {
			continue
		}
		if !strings.EqualFold(record.ComparisonKey, comparisonKey) {
			continue
		}
		if latest == nil || !record.OccurredAt.Before(latest.OccurredAt) {
			current := record
			latest = &current
		}
	}
	return latest
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewState(run *secureCellRun, comparisonKey string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus, string, *time.Time, int) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusUnreviewed, "", nil, 0
	}
	comparisonKey = strings.TrimSpace(comparisonKey)
	status := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusUnreviewed
	var actor string
	var at *time.Time
	total := 0
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionFromTransition(run, transition)
		if !ok || !strings.EqualFold(record.ComparisonKey, comparisonKey) {
			continue
		}
		total++
		if at == nil || !record.OccurredAt.Before(at.UTC()) {
			status = record.ReviewStatus
			actor = record.ActorDID
			recordAt := record.OccurredAt.UTC()
			at = &recordAt
		}
	}
	return status, actor, at, total
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionTypeFromTransitionAction(action string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionType, bool) {
	switch strings.TrimSpace(action) {
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_acknowledged":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionAcknowledge, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_disputed":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionDispute, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_resolved":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionResolve, true
	default:
		return "", false
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusFromActionType(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionType) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionAcknowledge:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusAcknowledged
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionDispute:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionResolve:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusResolved
	default:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusUnreviewed
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationTransitionSuffix(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionType) string {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionAcknowledge:
		return "federation_incident_directive_extension_appeal_reconciliation_acknowledged"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionDispute:
		return "federation_incident_directive_extension_appeal_reconciliation_disputed"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationActionResolve:
		return "federation_incident_directive_extension_appeal_reconciliation_resolved"
	default:
		return "federation_incident_directive_extension_appeal_reconciliation_updated"
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleDigest(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle) [32]byte {
	clone := *bundle
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}
