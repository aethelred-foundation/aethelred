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

const secureCellFederationIncidentReportReconciliationBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentReportReviewStatus tracks the latest governed
// review posture over one bilateral incident-report reconciliation key.
type SecureCellFederationIncidentReportReviewStatus string

const (
	SecureCellFederationIncidentReportReviewStatusUnreviewed   SecureCellFederationIncidentReportReviewStatus = "unreviewed"
	SecureCellFederationIncidentReportReviewStatusAcknowledged SecureCellFederationIncidentReportReviewStatus = "acknowledged"
	SecureCellFederationIncidentReportReviewStatusDisputed     SecureCellFederationIncidentReportReviewStatus = "disputed"
	SecureCellFederationIncidentReportReviewStatusResolved     SecureCellFederationIncidentReportReviewStatus = "resolved"
)

// SecureCellFederationIncidentReportReconciliationActionType captures one
// governed operator action over a bilateral report reconciliation.
type SecureCellFederationIncidentReportReconciliationActionType string

const (
	SecureCellFederationIncidentReportReconciliationActionAcknowledge SecureCellFederationIncidentReportReconciliationActionType = "acknowledge"
	SecureCellFederationIncidentReportReconciliationActionDispute     SecureCellFederationIncidentReportReconciliationActionType = "dispute"
	SecureCellFederationIncidentReportReconciliationActionResolve     SecureCellFederationIncidentReportReconciliationActionType = "resolve"
)

// SecureCellFederationIncidentReportReconciliationAcknowledgeRequest marks one
// bilateral incident-report reconciliation as reviewed and accepted.
type SecureCellFederationIncidentReportReconciliationAcknowledgeRequest struct {
	ActorDID string            `json:"actor_did,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportReconciliationDisputeRequest records one
// challenge against an imported or mismatched counterparty incident report.
type SecureCellFederationIncidentReportReconciliationDisputeRequest struct {
	ActorDID    string            `json:"actor_did,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Divergences []string          `json:"divergences,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportReconciliationResolveRequest records one
// bilateral decision that the disputed report posture has been resolved.
type SecureCellFederationIncidentReportReconciliationResolveRequest struct {
	ActorDID string            `json:"actor_did,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportReconciliationActionFilter narrows
// operator views across governed report-reconciliation reviews.
type SecureCellFederationIncidentReportReconciliationActionFilter struct {
	CellID         string                                                     `json:"cell_id,omitempty"`
	OrganizationID string                                                     `json:"organization_id,omitempty"`
	IncidentID     string                                                     `json:"incident_id,omitempty"`
	ComparisonKey  string                                                     `json:"comparison_key,omitempty"`
	Action         SecureCellFederationIncidentReportReconciliationActionType `json:"action,omitempty"`
	ReviewStatus   SecureCellFederationIncidentReportReviewStatus             `json:"review_status,omitempty"`
	ActorDID       string                                                     `json:"actor_did,omitempty"`
	Limit          int                                                        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentReportReconciliationActionRecord is the
// operator-facing evidence record for one governed reconciliation action.
type SecureCellFederationIncidentReportReconciliationActionRecord struct {
	CellID                 string                                                     `json:"cell_id"`
	CellName               string                                                     `json:"cell_name,omitempty"`
	CellStatus             SecureCellStatus                                           `json:"cell_status"`
	Jurisdiction           string                                                     `json:"jurisdiction,omitempty"`
	OrganizationID         string                                                     `json:"organization_id"`
	SponsorOfRecord        string                                                     `json:"sponsor_of_record,omitempty"`
	OrganizationName       string                                                     `json:"organization_name,omitempty"`
	ComparisonKey          string                                                     `json:"comparison_key"`
	IncidentID             string                                                     `json:"incident_id,omitempty"`
	LocalReportID          string                                                     `json:"local_report_id,omitempty"`
	LocalResponseID        string                                                     `json:"local_response_id,omitempty"`
	CounterpartySnapshotID string                                                     `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyBundleID   string                                                     `json:"counterparty_bundle_id,omitempty"`
	CounterpartyReportID   string                                                     `json:"counterparty_report_id,omitempty"`
	CounterpartyResponseID string                                                     `json:"counterparty_response_id,omitempty"`
	ReconciliationStatus   SecureCellFederationIncidentReportReconciliationStatus     `json:"reconciliation_status"`
	ReviewStatus           SecureCellFederationIncidentReportReviewStatus             `json:"review_status"`
	Action                 SecureCellFederationIncidentReportReconciliationActionType `json:"action"`
	TransitionID           string                                                     `json:"transition_id,omitempty"`
	PolicyReceiptID        string                                                     `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash      string                                                     `json:"policy_receipt_hash,omitempty"`
	SealID                 string                                                     `json:"seal_id,omitempty"`
	TraceLinkID            string                                                     `json:"trace_link_id,omitempty"`
	ActorDID               string                                                     `json:"actor_did,omitempty"`
	Reason                 string                                                     `json:"reason,omitempty"`
	Divergences            []string                                                   `json:"divergences,omitempty"`
	Metadata               map[string]string                                          `json:"metadata,omitempty"`
	OccurredAt             time.Time                                                  `json:"occurred_at"`
}

// SecureCellFederationIncidentReportReconciliationBundleSignature captures
// detached signer metadata for one reconciliation evidence bundle.
type SecureCellFederationIncidentReportReconciliationBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentReportReconciliationBundle is the signed
// auditor-facing package for one bilateral incident-report reconciliation.
type SecureCellFederationIncidentReportReconciliationBundle struct {
	ID                      string                                                           `json:"id"`
	Version                 string                                                           `json:"version"`
	Name                    string                                                           `json:"name"`
	GeneratedAt             time.Time                                                        `json:"generated_at"`
	ExpiresAt               *time.Time                                                       `json:"expires_at,omitempty"`
	CellID                  string                                                           `json:"cell_id"`
	CellName                string                                                           `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                                                 `json:"cell_status"`
	Jurisdiction            string                                                           `json:"jurisdiction,omitempty"`
	Framework               string                                                           `json:"framework,omitempty"`
	Organization            SecureCellFederationOrganizationSummary                          `json:"organization"`
	Reconciliation          SecureCellFederationIncidentReportReconciliationSummary          `json:"reconciliation"`
	LocalReport             *SecureCellFederationIncidentReportSummary                       `json:"local_report,omitempty"`
	CounterpartyReport      *SecureCellFederationCounterpartyIncidentReportSummary           `json:"counterparty_report,omitempty"`
	Actions                 []SecureCellFederationIncidentReportReconciliationActionRecord   `json:"actions,omitempty"`
	Contracts               []SecureCellFederationContractSummary                            `json:"contracts,omitempty"`
	Controls                []SecureCellFederationTrustPackControl                           `json:"controls,omitempty"`
	OperatorSurfaces        []SecureCellFederationOperatorSurface                            `json:"operator_surfaces,omitempty"`
	ControlLedgerID         string                                                           `json:"control_ledger_id,omitempty"`
	ControlLedgerHash       string                                                           `json:"control_ledger_hash,omitempty"`
	PortablePackageHash     string                                                           `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                                             `json:"portable_package_signed"`
	PortablePackageAnchored bool                                                             `json:"portable_package_anchored"`
	ContentHash             string                                                           `json:"content_hash,omitempty"`
	Signature               *SecureCellFederationIncidentReportReconciliationBundleSignature `json:"signature,omitempty"`
	Metadata                map[string]string                                                `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportReconciliationBundleOptions lets callers
// tune bundle identity, expiry, and operator-surface hints.
type SecureCellFederationIncidentReportReconciliationBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

func (s *Service) AcknowledgeFederationIncidentReportReconciliation(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentReportReconciliationAcknowledgeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentReportReconciliationAction(ctx, cellID, comparisonKey, secureCellFederationIncidentReportReconciliationActionSpec{
		stage:    "acknowledge_federation_incident_report_reconciliation",
		action:   SecureCellFederationIncidentReportReconciliationActionAcknowledge,
		review:   SecureCellFederationIncidentReportReviewStatusAcknowledged,
		actorDID: req.ActorDID,
		reason:   req.Reason,
		metadata: req.Metadata,
	})
}

func (s *Service) DisputeFederationIncidentReportReconciliation(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentReportReconciliationDisputeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentReportReconciliationAction(ctx, cellID, comparisonKey, secureCellFederationIncidentReportReconciliationActionSpec{
		stage:       "dispute_federation_incident_report_reconciliation",
		action:      SecureCellFederationIncidentReportReconciliationActionDispute,
		review:      SecureCellFederationIncidentReportReviewStatusDisputed,
		actorDID:    req.ActorDID,
		reason:      req.Reason,
		metadata:    req.Metadata,
		divergences: req.Divergences,
	})
}

func (s *Service) ResolveFederationIncidentReportReconciliation(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentReportReconciliationResolveRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentReportReconciliationAction(ctx, cellID, comparisonKey, secureCellFederationIncidentReportReconciliationActionSpec{
		stage:    "resolve_federation_incident_report_reconciliation",
		action:   SecureCellFederationIncidentReportReconciliationActionResolve,
		review:   SecureCellFederationIncidentReportReviewStatusResolved,
		actorDID: req.ActorDID,
		reason:   req.Reason,
		metadata: req.Metadata,
	})
}

func (s *Service) BuildFederationIncidentReportReconciliationBundle(ctx context.Context, cellID string, comparisonKey string, options SecureCellFederationIncidentReportReconciliationBundleOptions) (*SecureCellFederationIncidentReportReconciliationBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report-reconciliation: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	reconciliation, err := secureCellFederationIncidentReportReconciliationSummaryByKey(run, comparisonKey)
	if err != nil {
		return nil, err
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, reconciliation.OrganizationID)
	if err != nil {
		return nil, err
	}

	var localReport *SecureCellFederationIncidentReportSummary
	if strings.TrimSpace(reconciliation.LocalReportID) != "" {
		_, reportSummary, _, _, err := secureCellFederationIncidentReportSummaryAndRefs(run, reconciliation.LocalReportID)
		if err == nil {
			localReport = &reportSummary
		}
	}

	var counterpartyReport *SecureCellFederationCounterpartyIncidentReportSummary
	if snapshot := secureCellLatestCounterpartyFederationIncidentReportsByKey(run)[reconciliation.ComparisonKey]; snapshot != nil {
		summary := secureCellFederationCounterpartyIncidentReportSummaryFromRun(run, *snapshot)
		counterpartyReport = &summary
	}

	actions, err := s.ListFederationIncidentReportReconciliationActions(ctx, SecureCellFederationIncidentReportReconciliationActionFilter{
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
	bundle := &SecureCellFederationIncidentReportReconciliationBundle{
		ID:                 firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%x-incident-report-reconciliation-bundle", run.result.CellID, sha256.Sum256([]byte(reconciliation.ComparisonKey)))),
		Version:            firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:               firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Incident Report Reconciliation Bundle %s", reconciliation.IncidentID)),
		GeneratedAt:        now,
		ExpiresAt:          cloneTimePtr(&expiresAt),
		CellID:             run.result.CellID,
		CellName:           run.result.Name,
		CellStatus:         run.result.Status,
		Jurisdiction:       run.request.Jurisdiction,
		Framework:          firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:       orgSummary,
		Reconciliation:     reconciliation,
		LocalReport:        localReport,
		CounterpartyReport: counterpartyReport,
		Actions:            append([]SecureCellFederationIncidentReportReconciliationActionRecord(nil), actions...),
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
	if s.config.FederationIncidentReportReconciliationBundleSigner != nil {
		if err := s.config.FederationIncidentReportReconciliationBundleSigner(ctx, bundle); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident-report-reconciliation: external bundle signing failed: %w", err)
		}
	} else if err := SignFederationIncidentReportReconciliationBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

func (s *Service) ListFederationIncidentReportReconciliationActions(_ context.Context, filter SecureCellFederationIncidentReportReconciliationActionFilter) ([]SecureCellFederationIncidentReportReconciliationActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentReportReconciliationActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentReportReconciliationActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentReportReconciliationActionFilter(record, filter) {
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

func VerifyFederationIncidentReportReconciliationBundle(bundle *SecureCellFederationIncidentReportReconciliationBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-report-reconciliation: bundle is required")
	}
	digest := secureCellFederationIncidentReportReconciliationBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-report-reconciliation: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-report-reconciliation: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-report-reconciliation: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentReportReconciliationBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-report-reconciliation: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-report-reconciliation: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-report-reconciliation: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-report-reconciliation: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-report-reconciliation: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-report-reconciliation: signature verification failed")
	}
	return nil
}

func SignFederationIncidentReportReconciliationBundleEd25519(bundle *SecureCellFederationIncidentReportReconciliationBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-report-reconciliation: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-report-reconciliation: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentReportReconciliationBundleDigest(bundle)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])

	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentReportReconciliationBundleSignature{
		Algorithm: secureCellFederationIncidentReportReconciliationBundleSignatureAlgorithmED25519,
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

type secureCellFederationIncidentReportReconciliationActionSpec struct {
	stage       string
	action      SecureCellFederationIncidentReportReconciliationActionType
	review      SecureCellFederationIncidentReportReviewStatus
	actorDID    string
	reason      string
	metadata    map[string]string
	divergences []string
}

func (s *Service) applyFederationIncidentReportReconciliationAction(ctx context.Context, cellID string, comparisonKey string, spec secureCellFederationIncidentReportReconciliationActionSpec) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report-reconciliation: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, err := secureCellFederationIncidentReportReconciliationSummaryByKey(run, comparisonKey)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(spec.actorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-report-reconciliation: %w: actor %q is not permitted to review reconciliation %q", ErrPolicyDenied, actorDID, comparisonKey)
	}
	latest := secureCellLatestFederationIncidentReportReconciliationAction(run, summary.ComparisonKey)
	switch spec.action {
	case SecureCellFederationIncidentReportReconciliationActionAcknowledge:
		if summary.Status != SecureCellFederationIncidentReportReconciliationStatusAligned {
			return nil, fmt.Errorf("securecells/federation-incident-report-reconciliation: only aligned reconciliations can be acknowledged")
		}
		if latest != nil && latest.ReviewStatus == SecureCellFederationIncidentReportReviewStatusAcknowledged {
			return nil, fmt.Errorf("securecells/federation-incident-report-reconciliation: reconciliation %q is already acknowledged", summary.ComparisonKey)
		}
	case SecureCellFederationIncidentReportReconciliationActionDispute:
		if strings.TrimSpace(summary.CounterpartySnapshotID) == "" {
			return nil, fmt.Errorf("securecells/federation-incident-report-reconciliation: counterparty report evidence is required to dispute reconciliation %q", summary.ComparisonKey)
		}
		if latest != nil && latest.ReviewStatus == SecureCellFederationIncidentReportReviewStatusDisputed {
			return nil, fmt.Errorf("securecells/federation-incident-report-reconciliation: reconciliation %q is already disputed", summary.ComparisonKey)
		}
	case SecureCellFederationIncidentReportReconciliationActionResolve:
		if latest == nil || latest.ReviewStatus != SecureCellFederationIncidentReportReviewStatusDisputed {
			return nil, fmt.Errorf("securecells/federation-incident-report-reconciliation: reconciliation %q must be disputed before it can be resolved", summary.ComparisonKey)
		}
	default:
		return nil, fmt.Errorf("securecells/federation-incident-report-reconciliation: unsupported action %q", spec.action)
	}

	divergences := uniqueTrimmedStrings(spec.divergences)
	if len(divergences) == 0 && spec.action == SecureCellFederationIncidentReportReconciliationActionDispute {
		divergences = append(divergences, summary.Divergences...)
	}

	receipt, err := s.evaluateStage(ctx, run.request, spec.stage, lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                            summary.OrganizationID,
		"federation_incident_id":                                summary.IncidentID,
		"federation_incident_report_reconciliation_key":         summary.ComparisonKey,
		"federation_incident_report_reconciliation_status":      string(summary.Status),
		"federation_incident_report_reconciliation_review":      string(spec.review),
		"federation_incident_report_reconciliation_action":      string(spec.action),
		"federation_incident_report_reconciliation_divergences": strings.Join(divergences, ","),
		"federation_incident_report_id":                         summary.LocalReportID,
		"federation_incident_response_id":                       summary.LocalResponseID,
		"federation_counterparty_incident_report_snapshot_id":   summary.CounterpartySnapshotID,
		"federation_counterparty_incident_report_bundle_id":     summary.CounterpartyBundleID,
		"federation_counterparty_incident_report_id":            summary.CounterpartyReportID,
		"transition_reason":                                     strings.TrimSpace(spec.reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-report-reconciliation: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentReportReconciliationTransitionSuffix(spec.action), summary.ComparisonKey),
		Action:           "secure_cell." + secureCellFederationIncidentReportReconciliationTransitionSuffix(spec.action),
		Actor:            actorDID,
		TargetType:       "federation_incident_report_reconciliation",
		TargetDID:        summary.ComparisonKey,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(spec.reason),
		Metadata: mergeStringMaps(spec.metadata, map[string]string{
			"federation_organization_id":                            summary.OrganizationID,
			"federation_sponsor_of_record":                          summary.SponsorOfRecord,
			"federation_organization_name":                          summary.OrganizationName,
			"federation_incident_id":                                summary.IncidentID,
			"federation_incident_report_reconciliation_key":         summary.ComparisonKey,
			"federation_incident_report_reconciliation_status":      string(summary.Status),
			"federation_incident_report_reconciliation_review":      string(spec.review),
			"federation_incident_report_reconciliation_action":      string(spec.action),
			"federation_incident_report_reconciliation_divergences": strings.Join(divergences, ","),
			"federation_incident_report_id":                         summary.LocalReportID,
			"federation_incident_response_id":                       summary.LocalResponseID,
			"federation_counterparty_incident_report_snapshot_id":   summary.CounterpartySnapshotID,
			"federation_counterparty_incident_report_bundle_id":     summary.CounterpartyBundleID,
			"federation_counterparty_incident_report_id":            summary.CounterpartyReportID,
			"federation_counterparty_incident_response_id":          summary.CounterpartyResponseID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellFederationIncidentReportReconciliationBundleDigest(bundle *SecureCellFederationIncidentReportReconciliationBundle) [32]byte {
	clone := *bundle
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}

func secureCellFederationIncidentReportReconciliationSummaryByKey(run *secureCellRun, comparisonKey string) (SecureCellFederationIncidentReportReconciliationSummary, error) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentReportReconciliationSummary{}, fmt.Errorf("securecells/federation-incident-report-reconciliation: secure cell result is required")
	}
	comparisonKey = strings.TrimSpace(comparisonKey)
	if comparisonKey == "" {
		return SecureCellFederationIncidentReportReconciliationSummary{}, fmt.Errorf("securecells/federation-incident-report-reconciliation: comparison key is required")
	}
	for _, item := range secureCellFederationIncidentReportReconciliationsFromRun(run) {
		if strings.EqualFold(item.ComparisonKey, comparisonKey) {
			return item, nil
		}
	}
	return SecureCellFederationIncidentReportReconciliationSummary{}, fmt.Errorf("securecells/federation-incident-report-reconciliation: reconciliation %q not found", comparisonKey)
}

func secureCellFederationIncidentReportReconciliationActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentReportReconciliationActionRecord, bool) {
	actionType, ok := secureCellFederationIncidentReportReconciliationActionTypeFromTransitionAction(transition.Action)
	if !ok {
		return SecureCellFederationIncidentReportReconciliationActionRecord{}, false
	}
	meta := cloneStringMap(transition.Metadata)
	record := SecureCellFederationIncidentReportReconciliationActionRecord{
		CellID:                 safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:               safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:             safeSecureCellStatus(run),
		Jurisdiction:           safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:         strings.TrimSpace(meta["federation_organization_id"]),
		SponsorOfRecord:        strings.TrimSpace(meta["federation_sponsor_of_record"]),
		OrganizationName:       strings.TrimSpace(meta["federation_organization_name"]),
		ComparisonKey:          strings.TrimSpace(meta["federation_incident_report_reconciliation_key"]),
		IncidentID:             strings.TrimSpace(meta["federation_incident_id"]),
		LocalReportID:          strings.TrimSpace(meta["federation_incident_report_id"]),
		LocalResponseID:        strings.TrimSpace(meta["federation_incident_response_id"]),
		CounterpartySnapshotID: strings.TrimSpace(meta["federation_counterparty_incident_report_snapshot_id"]),
		CounterpartyBundleID:   strings.TrimSpace(meta["federation_counterparty_incident_report_bundle_id"]),
		CounterpartyReportID:   strings.TrimSpace(meta["federation_counterparty_incident_report_id"]),
		CounterpartyResponseID: strings.TrimSpace(meta["federation_counterparty_incident_response_id"]),
		ReconciliationStatus:   SecureCellFederationIncidentReportReconciliationStatus(strings.TrimSpace(meta["federation_incident_report_reconciliation_status"])),
		ReviewStatus:           SecureCellFederationIncidentReportReviewStatus(strings.TrimSpace(meta["federation_incident_report_reconciliation_review"])),
		Action:                 actionType,
		TransitionID:           strings.TrimSpace(transition.ID),
		ActorDID:               strings.TrimSpace(transition.Actor),
		Reason:                 firstNonEmpty(strings.TrimSpace(transition.Reason), strings.TrimSpace(meta["transition_reason"])),
		Divergences:            uniqueTrimmedStrings(strings.Split(strings.TrimSpace(meta["federation_incident_report_reconciliation_divergences"]), ",")),
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
		if summary, err := secureCellFederationIncidentReportReconciliationSummaryByKey(run, record.ComparisonKey); err == nil {
			record.ReconciliationStatus = summary.Status
			record.OrganizationName = firstNonEmpty(record.OrganizationName, summary.OrganizationName)
			record.SponsorOfRecord = firstNonEmpty(record.SponsorOfRecord, summary.SponsorOfRecord)
			record.IncidentID = firstNonEmpty(record.IncidentID, summary.IncidentID)
			record.LocalReportID = firstNonEmpty(record.LocalReportID, summary.LocalReportID)
			record.LocalResponseID = firstNonEmpty(record.LocalResponseID, summary.LocalResponseID)
			record.CounterpartySnapshotID = firstNonEmpty(record.CounterpartySnapshotID, summary.CounterpartySnapshotID)
			record.CounterpartyBundleID = firstNonEmpty(record.CounterpartyBundleID, summary.CounterpartyBundleID)
			record.CounterpartyReportID = firstNonEmpty(record.CounterpartyReportID, summary.CounterpartyReportID)
			record.CounterpartyResponseID = firstNonEmpty(record.CounterpartyResponseID, summary.CounterpartyResponseID)
			if len(record.Divergences) == 0 {
				record.Divergences = append([]string(nil), summary.Divergences...)
			}
		}
	}
	if record.ReviewStatus == "" {
		record.ReviewStatus = secureCellFederationIncidentReportReviewStatusFromActionType(actionType)
	}
	return record, true
}

func matchesSecureCellFederationIncidentReportReconciliationActionFilter(item SecureCellFederationIncidentReportReconciliationActionRecord, filter SecureCellFederationIncidentReportReconciliationActionFilter) bool {
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

func secureCellLatestFederationIncidentReportReconciliationAction(run *secureCellRun, comparisonKey string) *SecureCellFederationIncidentReportReconciliationActionRecord {
	if run == nil || run.result == nil {
		return nil
	}
	comparisonKey = strings.TrimSpace(comparisonKey)
	var latest *SecureCellFederationIncidentReportReconciliationActionRecord
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentReportReconciliationActionFromTransition(run, transition)
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

func secureCellFederationIncidentReportReconciliationReviewState(run *secureCellRun, comparisonKey string) (SecureCellFederationIncidentReportReviewStatus, string, *time.Time, int) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentReportReviewStatusUnreviewed, "", nil, 0
	}
	comparisonKey = strings.TrimSpace(comparisonKey)
	status := SecureCellFederationIncidentReportReviewStatusUnreviewed
	var actor string
	var at *time.Time
	total := 0
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentReportReconciliationActionFromTransition(run, transition)
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

func secureCellFederationIncidentReportReconciliationActionTypeFromTransitionAction(action string) (SecureCellFederationIncidentReportReconciliationActionType, bool) {
	switch strings.TrimSpace(action) {
	case "secure_cell.federation_incident_report_reconciliation_acknowledged":
		return SecureCellFederationIncidentReportReconciliationActionAcknowledge, true
	case "secure_cell.federation_incident_report_reconciliation_disputed":
		return SecureCellFederationIncidentReportReconciliationActionDispute, true
	case "secure_cell.federation_incident_report_reconciliation_resolved":
		return SecureCellFederationIncidentReportReconciliationActionResolve, true
	default:
		return "", false
	}
}

func secureCellFederationIncidentReportReviewStatusFromActionType(action SecureCellFederationIncidentReportReconciliationActionType) SecureCellFederationIncidentReportReviewStatus {
	switch action {
	case SecureCellFederationIncidentReportReconciliationActionAcknowledge:
		return SecureCellFederationIncidentReportReviewStatusAcknowledged
	case SecureCellFederationIncidentReportReconciliationActionDispute:
		return SecureCellFederationIncidentReportReviewStatusDisputed
	case SecureCellFederationIncidentReportReconciliationActionResolve:
		return SecureCellFederationIncidentReportReviewStatusResolved
	default:
		return SecureCellFederationIncidentReportReviewStatusUnreviewed
	}
}

func secureCellFederationIncidentReportReconciliationTransitionSuffix(action SecureCellFederationIncidentReportReconciliationActionType) string {
	switch action {
	case SecureCellFederationIncidentReportReconciliationActionAcknowledge:
		return "federation_incident_report_reconciliation_acknowledged"
	case SecureCellFederationIncidentReportReconciliationActionDispute:
		return "federation_incident_report_reconciliation_disputed"
	case SecureCellFederationIncidentReportReconciliationActionResolve:
		return "federation_incident_report_reconciliation_resolved"
	default:
		return "federation_incident_report_reconciliation_updated"
	}
}
