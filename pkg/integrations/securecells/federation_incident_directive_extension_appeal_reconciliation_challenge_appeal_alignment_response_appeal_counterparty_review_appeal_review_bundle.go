package securecells

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleSignature
// carries the detached signature over one portable imported appeal-board review
// bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle
// packages the governed local review trail over one imported bilateral
// rehearing-board bundle into a single signed auditor artifact.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle struct {
	ID                                 string                                                                                                                                                 `json:"id"`
	Version                            string                                                                                                                                                 `json:"version"`
	Name                               string                                                                                                                                                 `json:"name"`
	GeneratedAt                        time.Time                                                                                                                                              `json:"generated_at"`
	ExpiresAt                          *time.Time                                                                                                                                             `json:"expires_at,omitempty"`
	CellID                             string                                                                                                                                                 `json:"cell_id"`
	CellName                           string                                                                                                                                                 `json:"cell_name,omitempty"`
	CellStatus                         SecureCellStatus                                                                                                                                       `json:"cell_status"`
	Jurisdiction                       string                                                                                                                                                 `json:"jurisdiction,omitempty"`
	Framework                          string                                                                                                                                                 `json:"framework,omitempty"`
	Organization                       SecureCellFederationOrganizationSummary                                                                                                                `json:"organization"`
	Review                             SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummary    `json:"review"`
	ReviewActions                      []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord         `json:"review_actions,omitempty"`
	LocalBoardResponseAppeal           *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary                                       `json:"local_board_response_appeal,omitempty"`
	LocalBoardResponseActions          []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord                                 `json:"local_board_response_actions,omitempty"`
	LocalBoardResponseRecusals         []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary                               `json:"local_board_response_recusals,omitempty"`
	LocalBoardResponseAutomation       []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionRecord                       `json:"local_board_response_automation,omitempty"`
	CounterpartyReviewAppealBundleHash string                                                                                                                                                 `json:"counterparty_review_appeal_bundle_hash,omitempty"`
	CounterpartyReviewBundleHash       string                                                                                                                                                 `json:"counterparty_review_bundle_hash,omitempty"`
	AlignmentResponseBundleHash        string                                                                                                                                                 `json:"alignment_response_bundle_hash,omitempty"`
	ChallengeAppealBundleHash          string                                                                                                                                                 `json:"challenge_appeal_bundle_hash,omitempty"`
	Controls                           []SecureCellFederationTrustPackControl                                                                                                                 `json:"controls,omitempty"`
	OperatorSurfaces                   []SecureCellFederationOperatorSurface                                                                                                                  `json:"operator_surfaces,omitempty"`
	ControlLedgerID                    string                                                                                                                                                 `json:"control_ledger_id,omitempty"`
	ControlLedgerHash                  string                                                                                                                                                 `json:"control_ledger_hash,omitempty"`
	PortablePackageHash                string                                                                                                                                                 `json:"portable_package_hash,omitempty"`
	PortablePackageSigned              bool                                                                                                                                                   `json:"portable_package_signed"`
	PortablePackageAnchored            bool                                                                                                                                                   `json:"portable_package_anchored"`
	ContentHash                        string                                                                                                                                                 `json:"content_hash,omitempty"`
	Signature                          *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleSignature `json:"signature,omitempty"`
	Metadata                           map[string]string                                                                                                                                      `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleOptions
// lets callers tune bundle identity and operator-surface hints.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

// BuildFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle
// returns the signed auditor bundle for one governed review trail over an
// imported bilateral rehearing-board bundle.
func (s *Service) BuildFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle(ctx context.Context, cellID string, snapshotID string, options SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleOptions) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	summary, err := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealSummaryBySnapshot(run, snapshotID)
	if err != nil {
		return nil, err
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, summary.OrganizationID)
	if err != nil {
		return nil, err
	}
	reviewActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewFilter{
		CellID:     cellID,
		SnapshotID: snapshotID,
	})
	if err != nil {
		return nil, err
	}
	importedBundle, err := s.GetFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealBundle(ctx, cellID, snapshotID)
	if err != nil {
		return nil, err
	}

	var localBoardAppeal *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary
	localBoardActions := []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord(nil)
	localBoardRecusals := []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary(nil)
	localBoardAutomation := []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionRecord(nil)
	if strings.TrimSpace(summary.CounterpartyBoardResponseAppealID) != "" {
		if appeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, summary.CounterpartyBoardResponseAppealID); err == nil && appeal != nil {
			copy := *appeal
			localBoardAppeal = &copy
		}
		localBoardActions, err = s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter{
			CellID:            cellID,
			ChallengeAppealID: summary.ChallengeAppealID,
			ResponseAppealID:  summary.CounterpartyBoardResponseAppealID,
		})
		if err != nil {
			return nil, err
		}
		localBoardRecusals, err = s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalFilter{
			CellID:            cellID,
			ChallengeAppealID: summary.ChallengeAppealID,
			ResponseAppealID:  summary.CounterpartyBoardResponseAppealID,
		})
		if err != nil {
			return nil, err
		}
		localBoardAutomation, err = s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionFilter{
			CellID:            cellID,
			ChallengeAppealID: summary.ChallengeAppealID,
			ResponseAppealID:  summary.CounterpartyBoardResponseAppealID,
		})
		if err != nil {
			return nil, err
		}
	}

	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	bundle := &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle{
		ID:                                 firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-counterparty-review-appeal-review-bundle", run.result.CellID, summary.SnapshotID)),
		Version:                            firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:                               firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Counterparty Ruling Appeal Review Bundle %s", summary.SnapshotID)),
		GeneratedAt:                        now,
		ExpiresAt:                          cloneTimePtr(&expiresAt),
		CellID:                             run.result.CellID,
		CellName:                           run.result.Name,
		CellStatus:                         run.result.Status,
		Jurisdiction:                       run.request.Jurisdiction,
		Framework:                          firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:                       orgSummary,
		Review:                             summary,
		ReviewActions:                      append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewRecord(nil), reviewActions...),
		LocalBoardResponseAppeal:           localBoardAppeal,
		LocalBoardResponseActions:          append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord(nil), localBoardActions...),
		LocalBoardResponseRecusals:         append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary(nil), localBoardRecusals...),
		LocalBoardResponseAutomation:       append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAutomationActionRecord(nil), localBoardAutomation...),
		CounterpartyReviewAppealBundleHash: strings.TrimSpace(importedBundle.ContentHash),
		CounterpartyReviewBundleHash:       strings.TrimSpace(importedBundle.CounterpartyReviewBundleHash),
		AlignmentResponseBundleHash:        strings.TrimSpace(importedBundle.AlignmentResponseBundleHash),
		ChallengeAppealBundleHash:          strings.TrimSpace(importedBundle.ChallengeAppealBundleHash),
		Controls:                           secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces:                   cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:                           cloneStringMap(options.Metadata),
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
	if s.config.FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleSigner != nil {
		if err := s.config.FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleSigner(ctx, bundle); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: external bundle signing failed: %w", err)
		}
	} else if err := SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

// VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle
// verifies the signature and content hash for one imported appeal-board review
// bundle.
func VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: bundle is required")
	}
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: signature verification failed")
	}
	return nil
}

// SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleEd25519
// signs one imported appeal-board review bundle with an ed25519 key.
func SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleEd25519(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal-counterparty-review-appeal-review-bundle: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleDigest(bundle)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])

	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleSignature{
		Algorithm: secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleSignatureAlgorithmED25519,
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundleDigest(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAppealReviewBundle) [32]byte {
	clone := *bundle
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}
