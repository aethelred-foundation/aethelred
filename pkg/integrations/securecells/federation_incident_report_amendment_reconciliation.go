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

const secureCellFederationIncidentReportAmendmentReconciliationBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentReportAmendmentReconciliationActionType captures
// one governed operator action over a bilateral amendment reconciliation.
type SecureCellFederationIncidentReportAmendmentReconciliationActionType string

const (
	SecureCellFederationIncidentReportAmendmentReconciliationActionAcknowledge SecureCellFederationIncidentReportAmendmentReconciliationActionType = "acknowledge"
	SecureCellFederationIncidentReportAmendmentReconciliationActionDispute     SecureCellFederationIncidentReportAmendmentReconciliationActionType = "dispute"
	SecureCellFederationIncidentReportAmendmentReconciliationActionResolve     SecureCellFederationIncidentReportAmendmentReconciliationActionType = "resolve"
)

// SecureCellFederationIncidentReportAmendmentReconciliationAcknowledgeRequest
// marks one bilateral amendment reconciliation as reviewed and accepted.
type SecureCellFederationIncidentReportAmendmentReconciliationAcknowledgeRequest struct {
	ActorDID string            `json:"actor_did,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationDisputeRequest
// records one challenge against an imported or mismatched amendment revision.
type SecureCellFederationIncidentReportAmendmentReconciliationDisputeRequest struct {
	ActorDID    string            `json:"actor_did,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Divergences []string          `json:"divergences,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationResolveRequest
// records one bilateral decision that an amendment dispute has been resolved.
type SecureCellFederationIncidentReportAmendmentReconciliationResolveRequest struct {
	ActorDID string            `json:"actor_did,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationActionFilter
// narrows operator views across governed amendment-reconciliation reviews.
type SecureCellFederationIncidentReportAmendmentReconciliationActionFilter struct {
	CellID         string                                                              `json:"cell_id,omitempty"`
	OrganizationID string                                                              `json:"organization_id,omitempty"`
	IncidentID     string                                                              `json:"incident_id,omitempty"`
	ComparisonKey  string                                                              `json:"comparison_key,omitempty"`
	Action         SecureCellFederationIncidentReportAmendmentReconciliationActionType `json:"action,omitempty"`
	ReviewStatus   SecureCellFederationIncidentReportReviewStatus                      `json:"review_status,omitempty"`
	ActorDID       string                                                              `json:"actor_did,omitempty"`
	Limit          int                                                                 `json:"limit,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationActionRecord is the
// operator-facing evidence record for one governed amendment reconciliation action.
type SecureCellFederationIncidentReportAmendmentReconciliationActionRecord struct {
	CellID                  string                                                              `json:"cell_id"`
	CellName                string                                                              `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                                                    `json:"cell_status"`
	Jurisdiction            string                                                              `json:"jurisdiction,omitempty"`
	OrganizationID          string                                                              `json:"organization_id"`
	SponsorOfRecord         string                                                              `json:"sponsor_of_record,omitempty"`
	OrganizationName        string                                                              `json:"organization_name,omitempty"`
	ComparisonKey           string                                                              `json:"comparison_key"`
	IncidentID              string                                                              `json:"incident_id,omitempty"`
	LocalReportID           string                                                              `json:"local_report_id,omitempty"`
	LocalResponseID         string                                                              `json:"local_response_id,omitempty"`
	LocalAmendmentID        string                                                              `json:"local_amendment_id,omitempty"`
	CounterpartySnapshotID  string                                                              `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyBundleID    string                                                              `json:"counterparty_bundle_id,omitempty"`
	CounterpartyReportID    string                                                              `json:"counterparty_report_id,omitempty"`
	CounterpartyResponseID  string                                                              `json:"counterparty_response_id,omitempty"`
	CounterpartyAmendmentID string                                                              `json:"counterparty_amendment_id,omitempty"`
	ReconciliationStatus    SecureCellFederationIncidentReportAmendmentReconciliationStatus     `json:"reconciliation_status"`
	ReviewStatus            SecureCellFederationIncidentReportReviewStatus                      `json:"review_status"`
	Action                  SecureCellFederationIncidentReportAmendmentReconciliationActionType `json:"action"`
	TransitionID            string                                                              `json:"transition_id,omitempty"`
	PolicyReceiptID         string                                                              `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash       string                                                              `json:"policy_receipt_hash,omitempty"`
	SealID                  string                                                              `json:"seal_id,omitempty"`
	TraceLinkID             string                                                              `json:"trace_link_id,omitempty"`
	ActorDID                string                                                              `json:"actor_did,omitempty"`
	Reason                  string                                                              `json:"reason,omitempty"`
	Divergences             []string                                                            `json:"divergences,omitempty"`
	Metadata                map[string]string                                                   `json:"metadata,omitempty"`
	OccurredAt              time.Time                                                           `json:"occurred_at"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationBundleSignature
// captures detached signer metadata for one reconciliation evidence bundle.
type SecureCellFederationIncidentReportAmendmentReconciliationBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationBundle is the signed
// auditor-facing package for one bilateral amendment reconciliation.
type SecureCellFederationIncidentReportAmendmentReconciliationBundle struct {
	ID                      string                                                                                   `json:"id"`
	Version                 string                                                                                   `json:"version"`
	Name                    string                                                                                   `json:"name"`
	GeneratedAt             time.Time                                                                                `json:"generated_at"`
	ExpiresAt               *time.Time                                                                               `json:"expires_at,omitempty"`
	CellID                  string                                                                                   `json:"cell_id"`
	CellName                string                                                                                   `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                                                                         `json:"cell_status"`
	Jurisdiction            string                                                                                   `json:"jurisdiction,omitempty"`
	Framework               string                                                                                   `json:"framework,omitempty"`
	Organization            SecureCellFederationOrganizationSummary                                                  `json:"organization"`
	Reconciliation          SecureCellFederationIncidentReportAmendmentReconciliationSummary                         `json:"reconciliation"`
	LocalAmendment          *SecureCellFederationIncidentReportAmendmentSummary                                      `json:"local_amendment,omitempty"`
	CounterpartyAmendment   *SecureCellFederationCounterpartyIncidentReportAmendmentSummary                          `json:"counterparty_amendment,omitempty"`
	Actions                 []SecureCellFederationIncidentReportAmendmentReconciliationActionRecord                  `json:"actions,omitempty"`
	Attestations            []SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord `json:"attestations,omitempty"`
	Contracts               []SecureCellFederationContractSummary                                                    `json:"contracts,omitempty"`
	Controls                []SecureCellFederationTrustPackControl                                                   `json:"controls,omitempty"`
	OperatorSurfaces        []SecureCellFederationOperatorSurface                                                    `json:"operator_surfaces,omitempty"`
	ControlLedgerID         string                                                                                   `json:"control_ledger_id,omitempty"`
	ControlLedgerHash       string                                                                                   `json:"control_ledger_hash,omitempty"`
	PortablePackageHash     string                                                                                   `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                                                                     `json:"portable_package_signed"`
	PortablePackageAnchored bool                                                                                     `json:"portable_package_anchored"`
	ContentHash             string                                                                                   `json:"content_hash,omitempty"`
	Signature               *SecureCellFederationIncidentReportAmendmentReconciliationBundleSignature                `json:"signature,omitempty"`
	Metadata                map[string]string                                                                        `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportAmendmentReconciliationBundleOptions lets
// callers tune bundle identity, expiry, and operator-surface hints.
type SecureCellFederationIncidentReportAmendmentReconciliationBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

func (s *Service) AcknowledgeFederationIncidentReportAmendmentReconciliation(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentReportAmendmentReconciliationAcknowledgeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentReportAmendmentReconciliationAction(ctx, cellID, comparisonKey, secureCellFederationIncidentReportAmendmentReconciliationActionSpec{
		stage:    "acknowledge_federation_incident_report_amendment_reconciliation",
		action:   SecureCellFederationIncidentReportAmendmentReconciliationActionAcknowledge,
		review:   SecureCellFederationIncidentReportReviewStatusAcknowledged,
		actorDID: req.ActorDID,
		reason:   req.Reason,
		metadata: req.Metadata,
	})
}

func (s *Service) DisputeFederationIncidentReportAmendmentReconciliation(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentReportAmendmentReconciliationDisputeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentReportAmendmentReconciliationAction(ctx, cellID, comparisonKey, secureCellFederationIncidentReportAmendmentReconciliationActionSpec{
		stage:       "dispute_federation_incident_report_amendment_reconciliation",
		action:      SecureCellFederationIncidentReportAmendmentReconciliationActionDispute,
		review:      SecureCellFederationIncidentReportReviewStatusDisputed,
		actorDID:    req.ActorDID,
		reason:      req.Reason,
		metadata:    req.Metadata,
		divergences: req.Divergences,
	})
}

func (s *Service) ResolveFederationIncidentReportAmendmentReconciliation(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentReportAmendmentReconciliationResolveRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentReportAmendmentReconciliationAction(ctx, cellID, comparisonKey, secureCellFederationIncidentReportAmendmentReconciliationActionSpec{
		stage:    "resolve_federation_incident_report_amendment_reconciliation",
		action:   SecureCellFederationIncidentReportAmendmentReconciliationActionResolve,
		review:   SecureCellFederationIncidentReportReviewStatusResolved,
		actorDID: req.ActorDID,
		reason:   req.Reason,
		metadata: req.Metadata,
	})
}

func (s *Service) BuildFederationIncidentReportAmendmentReconciliationBundle(ctx context.Context, cellID string, comparisonKey string, options SecureCellFederationIncidentReportAmendmentReconciliationBundleOptions) (*SecureCellFederationIncidentReportAmendmentReconciliationBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	reconciliation, err := secureCellFederationIncidentReportAmendmentReconciliationSummaryByKey(run, comparisonKey)
	if err != nil {
		return nil, err
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, reconciliation.OrganizationID)
	if err != nil {
		return nil, err
	}

	var localAmendment *SecureCellFederationIncidentReportAmendmentSummary
	if strings.TrimSpace(reconciliation.LocalAmendmentID) != "" {
		_, _, amendmentSummary, _, _, _, err := secureCellFederationIncidentReportAmendmentSummaryAndRefs(run, reconciliation.LocalAmendmentID)
		if err == nil {
			localAmendment = &amendmentSummary
		}
	}

	var counterpartyAmendment *SecureCellFederationCounterpartyIncidentReportAmendmentSummary
	if snapshot := secureCellLatestCounterpartyFederationIncidentReportAmendmentsByKey(run)[reconciliation.ComparisonKey]; snapshot != nil {
		summary := secureCellFederationCounterpartyIncidentReportAmendmentSummaryFromRun(run, *snapshot)
		counterpartyAmendment = &summary
	}

	actions, err := s.ListFederationIncidentReportAmendmentReconciliationActions(ctx, SecureCellFederationIncidentReportAmendmentReconciliationActionFilter{
		CellID:        cellID,
		ComparisonKey: comparisonKey,
	})
	if err != nil {
		return nil, err
	}
	attestations, err := s.ListFederationIncidentReportAmendmentReconciliationCounterpartyAttestations(ctx, SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter{
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
	bundle := &SecureCellFederationIncidentReportAmendmentReconciliationBundle{
		ID:                    firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%x-incident-report-amendment-reconciliation-bundle", run.result.CellID, sha256.Sum256([]byte(reconciliation.ComparisonKey)))),
		Version:               firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:                  firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Incident Report Amendment Reconciliation Bundle %s", reconciliation.IncidentID)),
		GeneratedAt:           now,
		ExpiresAt:             cloneTimePtr(&expiresAt),
		CellID:                run.result.CellID,
		CellName:              run.result.Name,
		CellStatus:            run.result.Status,
		Jurisdiction:          run.request.Jurisdiction,
		Framework:             firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:          orgSummary,
		Reconciliation:        reconciliation,
		LocalAmendment:        localAmendment,
		CounterpartyAmendment: counterpartyAmendment,
		Actions:               append([]SecureCellFederationIncidentReportAmendmentReconciliationActionRecord(nil), actions...),
		Attestations:          append([]SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord(nil), attestations...),
		Contracts:             secureCellFederationContractSummariesForOrganization(run, reconciliation.OrganizationID),
		Controls:              secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces:      cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:              cloneStringMap(options.Metadata),
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
	if s.config.FederationIncidentReportAmendmentReconciliationBundleSigner != nil {
		if err := s.config.FederationIncidentReportAmendmentReconciliationBundleSigner(ctx, bundle); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: external bundle signing failed: %w", err)
		}
	} else if err := SignFederationIncidentReportAmendmentReconciliationBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

func (s *Service) ListFederationIncidentReportAmendmentReconciliationActions(_ context.Context, filter SecureCellFederationIncidentReportAmendmentReconciliationActionFilter) ([]SecureCellFederationIncidentReportAmendmentReconciliationActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentReportAmendmentReconciliationActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentReportAmendmentReconciliationActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentReportAmendmentReconciliationActionFilter(record, filter) {
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

func VerifyFederationIncidentReportAmendmentReconciliationBundle(bundle *SecureCellFederationIncidentReportAmendmentReconciliationBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: bundle is required")
	}
	digest := secureCellFederationIncidentReportAmendmentReconciliationBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentReportAmendmentReconciliationBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: signature verification failed")
	}
	return nil
}

func SignFederationIncidentReportAmendmentReconciliationBundleEd25519(bundle *SecureCellFederationIncidentReportAmendmentReconciliationBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentReportAmendmentReconciliationBundleDigest(bundle)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])

	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentReportAmendmentReconciliationBundleSignature{
		Algorithm: secureCellFederationIncidentReportAmendmentReconciliationBundleSignatureAlgorithmED25519,
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

type secureCellFederationIncidentReportAmendmentReconciliationActionSpec struct {
	stage       string
	action      SecureCellFederationIncidentReportAmendmentReconciliationActionType
	review      SecureCellFederationIncidentReportReviewStatus
	actorDID    string
	reason      string
	metadata    map[string]string
	divergences []string
}

func (s *Service) applyFederationIncidentReportAmendmentReconciliationAction(ctx context.Context, cellID string, comparisonKey string, spec secureCellFederationIncidentReportAmendmentReconciliationActionSpec) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, err := secureCellFederationIncidentReportAmendmentReconciliationSummaryByKey(run, comparisonKey)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(spec.actorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: %w: actor %q is not permitted to review reconciliation %q", ErrPolicyDenied, actorDID, comparisonKey)
	}
	latest := secureCellLatestFederationIncidentReportAmendmentReconciliationAction(run, summary.ComparisonKey)
	switch spec.action {
	case SecureCellFederationIncidentReportAmendmentReconciliationActionAcknowledge:
		if summary.Status != SecureCellFederationIncidentReportAmendmentReconciliationStatusAligned {
			return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: only aligned reconciliations can be acknowledged")
		}
		if latest != nil && latest.ReviewStatus == SecureCellFederationIncidentReportReviewStatusAcknowledged {
			return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: reconciliation %q is already acknowledged", summary.ComparisonKey)
		}
	case SecureCellFederationIncidentReportAmendmentReconciliationActionDispute:
		if strings.TrimSpace(summary.CounterpartySnapshotID) == "" {
			return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: counterparty amendment evidence is required to dispute reconciliation %q", summary.ComparisonKey)
		}
		if latest != nil && latest.ReviewStatus == SecureCellFederationIncidentReportReviewStatusDisputed {
			return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: reconciliation %q is already disputed", summary.ComparisonKey)
		}
	case SecureCellFederationIncidentReportAmendmentReconciliationActionResolve:
		if latest == nil || latest.ReviewStatus != SecureCellFederationIncidentReportReviewStatusDisputed {
			return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: reconciliation %q must be disputed before it can be resolved", summary.ComparisonKey)
		}
	default:
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: unsupported action %q", spec.action)
	}

	divergences := uniqueTrimmedStrings(spec.divergences)
	if len(divergences) == 0 && spec.action == SecureCellFederationIncidentReportAmendmentReconciliationActionDispute {
		divergences = append(divergences, summary.Divergences...)
	}

	receipt, err := s.evaluateStage(ctx, run.request, spec.stage, lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                      summary.OrganizationID,
		"federation_incident_id":                                          summary.IncidentID,
		"federation_incident_report_amendment_reconciliation_key":         summary.ComparisonKey,
		"federation_incident_report_amendment_reconciliation_status":      string(summary.Status),
		"federation_incident_report_amendment_reconciliation_review":      string(spec.review),
		"federation_incident_report_amendment_reconciliation_action":      string(spec.action),
		"federation_incident_report_amendment_reconciliation_divergences": strings.Join(divergences, ","),
		"federation_incident_report_id":                                   summary.LocalReportID,
		"federation_incident_response_id":                                 summary.LocalResponseID,
		"federation_incident_report_amendment_id":                         summary.LocalAmendmentID,
		"federation_counterparty_incident_report_amendment_snapshot_id":   summary.CounterpartySnapshotID,
		"federation_counterparty_incident_report_amendment_bundle_id":     summary.CounterpartyBundleID,
		"federation_counterparty_incident_report_id":                      summary.CounterpartyReportID,
		"federation_counterparty_incident_response_id":                    summary.CounterpartyResponseID,
		"federation_counterparty_incident_report_amendment_id":            summary.CounterpartyAmendmentID,
		"transition_reason":                                               strings.TrimSpace(spec.reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentReportAmendmentReconciliationTransitionSuffix(spec.action), summary.ComparisonKey),
		Action:           "secure_cell." + secureCellFederationIncidentReportAmendmentReconciliationTransitionSuffix(spec.action),
		Actor:            actorDID,
		TargetType:       "federation_incident_report_amendment_reconciliation",
		TargetDID:        summary.ComparisonKey,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(spec.reason),
		Metadata: mergeStringMaps(spec.metadata, map[string]string{
			"federation_organization_id":                                      summary.OrganizationID,
			"federation_sponsor_of_record":                                    summary.SponsorOfRecord,
			"federation_organization_name":                                    summary.OrganizationName,
			"federation_incident_id":                                          summary.IncidentID,
			"federation_incident_report_amendment_reconciliation_key":         summary.ComparisonKey,
			"federation_incident_report_amendment_reconciliation_status":      string(summary.Status),
			"federation_incident_report_amendment_reconciliation_review":      string(spec.review),
			"federation_incident_report_amendment_reconciliation_action":      string(spec.action),
			"federation_incident_report_amendment_reconciliation_divergences": strings.Join(divergences, ","),
			"federation_incident_report_id":                                   summary.LocalReportID,
			"federation_incident_response_id":                                 summary.LocalResponseID,
			"federation_incident_report_amendment_id":                         summary.LocalAmendmentID,
			"federation_counterparty_incident_report_amendment_snapshot_id":   summary.CounterpartySnapshotID,
			"federation_counterparty_incident_report_amendment_bundle_id":     summary.CounterpartyBundleID,
			"federation_counterparty_incident_report_id":                      summary.CounterpartyReportID,
			"federation_counterparty_incident_response_id":                    summary.CounterpartyResponseID,
			"federation_counterparty_incident_report_amendment_id":            summary.CounterpartyAmendmentID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellFederationIncidentReportAmendmentReconciliationBundleDigest(bundle *SecureCellFederationIncidentReportAmendmentReconciliationBundle) [32]byte {
	clone := *bundle
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}

func secureCellFederationIncidentReportAmendmentReconciliationSummaryByKey(run *secureCellRun, comparisonKey string) (SecureCellFederationIncidentReportAmendmentReconciliationSummary, error) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentReportAmendmentReconciliationSummary{}, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: secure cell result is required")
	}
	comparisonKey = strings.TrimSpace(comparisonKey)
	if comparisonKey == "" {
		return SecureCellFederationIncidentReportAmendmentReconciliationSummary{}, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: comparison key is required")
	}
	for _, item := range secureCellFederationIncidentReportAmendmentReconciliationsFromRun(run) {
		if strings.EqualFold(item.ComparisonKey, comparisonKey) {
			return item, nil
		}
	}
	return SecureCellFederationIncidentReportAmendmentReconciliationSummary{}, fmt.Errorf("securecells/federation-incident-report-amendment-reconciliation: reconciliation %q not found", comparisonKey)
}

func secureCellFederationIncidentReportAmendmentReconciliationActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentReportAmendmentReconciliationActionRecord, bool) {
	actionType, ok := secureCellFederationIncidentReportAmendmentReconciliationActionTypeFromTransitionAction(transition.Action)
	if !ok {
		return SecureCellFederationIncidentReportAmendmentReconciliationActionRecord{}, false
	}
	meta := cloneStringMap(transition.Metadata)
	record := SecureCellFederationIncidentReportAmendmentReconciliationActionRecord{
		CellID:                  safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:              safeSecureCellStatus(run),
		Jurisdiction:            safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:          strings.TrimSpace(meta["federation_organization_id"]),
		SponsorOfRecord:         strings.TrimSpace(meta["federation_sponsor_of_record"]),
		OrganizationName:        strings.TrimSpace(meta["federation_organization_name"]),
		ComparisonKey:           strings.TrimSpace(meta["federation_incident_report_amendment_reconciliation_key"]),
		IncidentID:              strings.TrimSpace(meta["federation_incident_id"]),
		LocalReportID:           strings.TrimSpace(meta["federation_incident_report_id"]),
		LocalResponseID:         strings.TrimSpace(meta["federation_incident_response_id"]),
		LocalAmendmentID:        strings.TrimSpace(meta["federation_incident_report_amendment_id"]),
		CounterpartySnapshotID:  strings.TrimSpace(meta["federation_counterparty_incident_report_amendment_snapshot_id"]),
		CounterpartyBundleID:    strings.TrimSpace(meta["federation_counterparty_incident_report_amendment_bundle_id"]),
		CounterpartyReportID:    strings.TrimSpace(meta["federation_counterparty_incident_report_id"]),
		CounterpartyResponseID:  strings.TrimSpace(meta["federation_counterparty_incident_response_id"]),
		CounterpartyAmendmentID: strings.TrimSpace(meta["federation_counterparty_incident_report_amendment_id"]),
		ReconciliationStatus:    SecureCellFederationIncidentReportAmendmentReconciliationStatus(strings.TrimSpace(meta["federation_incident_report_amendment_reconciliation_status"])),
		ReviewStatus:            SecureCellFederationIncidentReportReviewStatus(strings.TrimSpace(meta["federation_incident_report_amendment_reconciliation_review"])),
		Action:                  actionType,
		TransitionID:            strings.TrimSpace(transition.ID),
		ActorDID:                strings.TrimSpace(transition.Actor),
		Reason:                  firstNonEmpty(strings.TrimSpace(transition.Reason), strings.TrimSpace(meta["transition_reason"])),
		Divergences:             uniqueTrimmedStrings(strings.Split(strings.TrimSpace(meta["federation_incident_report_amendment_reconciliation_divergences"]), ",")),
		Metadata:                meta,
		OccurredAt:              transition.OccurredAt.UTC(),
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
		if summary, err := secureCellFederationIncidentReportAmendmentReconciliationSummaryByKey(run, record.ComparisonKey); err == nil {
			record.ReconciliationStatus = summary.Status
			record.OrganizationName = firstNonEmpty(record.OrganizationName, summary.OrganizationName)
			record.SponsorOfRecord = firstNonEmpty(record.SponsorOfRecord, summary.SponsorOfRecord)
			record.IncidentID = firstNonEmpty(record.IncidentID, summary.IncidentID)
			record.LocalReportID = firstNonEmpty(record.LocalReportID, summary.LocalReportID)
			record.LocalResponseID = firstNonEmpty(record.LocalResponseID, summary.LocalResponseID)
			record.LocalAmendmentID = firstNonEmpty(record.LocalAmendmentID, summary.LocalAmendmentID)
			record.CounterpartySnapshotID = firstNonEmpty(record.CounterpartySnapshotID, summary.CounterpartySnapshotID)
			record.CounterpartyBundleID = firstNonEmpty(record.CounterpartyBundleID, summary.CounterpartyBundleID)
			record.CounterpartyReportID = firstNonEmpty(record.CounterpartyReportID, summary.CounterpartyReportID)
			record.CounterpartyResponseID = firstNonEmpty(record.CounterpartyResponseID, summary.CounterpartyResponseID)
			record.CounterpartyAmendmentID = firstNonEmpty(record.CounterpartyAmendmentID, summary.CounterpartyAmendmentID)
			if len(record.Divergences) == 0 {
				record.Divergences = append([]string(nil), summary.Divergences...)
			}
		}
	}
	if record.ReviewStatus == "" {
		record.ReviewStatus = secureCellFederationIncidentReportAmendmentReviewStatusFromActionType(actionType)
	}
	return record, true
}

func matchesSecureCellFederationIncidentReportAmendmentReconciliationActionFilter(item SecureCellFederationIncidentReportAmendmentReconciliationActionRecord, filter SecureCellFederationIncidentReportAmendmentReconciliationActionFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(item.OrganizationID, strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.IncidentID != "" && !strings.EqualFold(item.IncidentID, strings.TrimSpace(filter.IncidentID)) {
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

func secureCellLatestFederationIncidentReportAmendmentReconciliationAction(run *secureCellRun, comparisonKey string) *SecureCellFederationIncidentReportAmendmentReconciliationActionRecord {
	if run == nil || run.result == nil {
		return nil
	}
	comparisonKey = strings.TrimSpace(comparisonKey)
	var latest *SecureCellFederationIncidentReportAmendmentReconciliationActionRecord
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentReportAmendmentReconciliationActionFromTransition(run, transition)
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

func secureCellFederationIncidentReportAmendmentReconciliationReviewState(run *secureCellRun, comparisonKey string) (SecureCellFederationIncidentReportReviewStatus, string, *time.Time, int) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentReportReviewStatusUnreviewed, "", nil, 0
	}
	comparisonKey = strings.TrimSpace(comparisonKey)
	status := SecureCellFederationIncidentReportReviewStatusUnreviewed
	var actor string
	var at *time.Time
	total := 0
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentReportAmendmentReconciliationActionFromTransition(run, transition)
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

func secureCellFederationIncidentReportAmendmentReconciliationActionTypeFromTransitionAction(action string) (SecureCellFederationIncidentReportAmendmentReconciliationActionType, bool) {
	switch strings.TrimSpace(action) {
	case "secure_cell.federation_incident_report_amendment_reconciliation_acknowledged":
		return SecureCellFederationIncidentReportAmendmentReconciliationActionAcknowledge, true
	case "secure_cell.federation_incident_report_amendment_reconciliation_disputed":
		return SecureCellFederationIncidentReportAmendmentReconciliationActionDispute, true
	case "secure_cell.federation_incident_report_amendment_reconciliation_resolved":
		return SecureCellFederationIncidentReportAmendmentReconciliationActionResolve, true
	default:
		return "", false
	}
}

func secureCellFederationIncidentReportAmendmentReviewStatusFromActionType(action SecureCellFederationIncidentReportAmendmentReconciliationActionType) SecureCellFederationIncidentReportReviewStatus {
	switch action {
	case SecureCellFederationIncidentReportAmendmentReconciliationActionAcknowledge:
		return SecureCellFederationIncidentReportReviewStatusAcknowledged
	case SecureCellFederationIncidentReportAmendmentReconciliationActionDispute:
		return SecureCellFederationIncidentReportReviewStatusDisputed
	case SecureCellFederationIncidentReportAmendmentReconciliationActionResolve:
		return SecureCellFederationIncidentReportReviewStatusResolved
	default:
		return SecureCellFederationIncidentReportReviewStatusUnreviewed
	}
}

func secureCellFederationIncidentReportAmendmentReconciliationTransitionSuffix(action SecureCellFederationIncidentReportAmendmentReconciliationActionType) string {
	switch action {
	case SecureCellFederationIncidentReportAmendmentReconciliationActionAcknowledge:
		return "federation_incident_report_amendment_reconciliation_acknowledged"
	case SecureCellFederationIncidentReportAmendmentReconciliationActionDispute:
		return "federation_incident_report_amendment_reconciliation_disputed"
	case SecureCellFederationIncidentReportAmendmentReconciliationActionResolve:
		return "federation_incident_report_amendment_reconciliation_resolved"
	default:
		return "federation_incident_report_amendment_reconciliation_updated"
	}
}
