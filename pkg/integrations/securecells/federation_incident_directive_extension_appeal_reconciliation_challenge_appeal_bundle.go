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

const secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSignature
// captures detached signer metadata for one portable reconciliation challenge
// appeal bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle
// is the signed auditor-facing package for one bilateral reconciliation
// challenge appeal board.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle struct {
	ID                           string                                                                                                    `json:"id"`
	Version                      string                                                                                                    `json:"version"`
	Name                         string                                                                                                    `json:"name"`
	GeneratedAt                  time.Time                                                                                                 `json:"generated_at"`
	ExpiresAt                    *time.Time                                                                                                `json:"expires_at,omitempty"`
	CellID                       string                                                                                                    `json:"cell_id"`
	CellName                     string                                                                                                    `json:"cell_name,omitempty"`
	CellStatus                   SecureCellStatus                                                                                          `json:"cell_status"`
	Jurisdiction                 string                                                                                                    `json:"jurisdiction,omitempty"`
	Framework                    string                                                                                                    `json:"framework,omitempty"`
	Organization                 SecureCellFederationOrganizationSummary                                                                   `json:"organization"`
	Reconciliation               SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary                                 `json:"reconciliation"`
	ChallengeSummary             SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary                        `json:"challenge_summary"`
	ChallengeAppealSummary       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary                  `json:"challenge_appeal_summary"`
	Actions                      []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord           `json:"actions,omitempty"`
	CounterpartyAlignmentActions []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionRecord  `json:"counterparty_alignment_actions,omitempty"`
	Recusals                     []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalSummary         `json:"recusals,omitempty"`
	AutomationActions            []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionRecord `json:"automation_actions,omitempty"`
	ReconciliationBundleHash     string                                                                                                    `json:"reconciliation_bundle_hash,omitempty"`
	Controls                     []SecureCellFederationTrustPackControl                                                                    `json:"controls,omitempty"`
	OperatorSurfaces             []SecureCellFederationOperatorSurface                                                                     `json:"operator_surfaces,omitempty"`
	ControlLedgerID              string                                                                                                    `json:"control_ledger_id,omitempty"`
	ControlLedgerHash            string                                                                                                    `json:"control_ledger_hash,omitempty"`
	PortablePackageHash          string                                                                                                    `json:"portable_package_hash,omitempty"`
	PortablePackageSigned        bool                                                                                                      `json:"portable_package_signed"`
	PortablePackageAnchored      bool                                                                                                      `json:"portable_package_anchored"`
	ContentHash                  string                                                                                                    `json:"content_hash,omitempty"`
	Signature                    *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSignature         `json:"signature,omitempty"`
	Metadata                     map[string]string                                                                                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleOptions
// lets callers tune bundle identity, expiry, and operator-surface hints.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

// BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle
// returns the signed auditor bundle for one reconciliation challenge appeal.
func (s *Service) BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle(ctx context.Context, cellID string, challengeAppealID string, options SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleOptions) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	challengeAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealByID(run, challengeAppealID)
	if err != nil {
		return nil, err
	}
	reconciliation, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationSummaryByKey(run, challengeAppeal.ComparisonKey)
	if err != nil {
		return nil, err
	}
	challengeSummary, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeByID(run, challengeAppeal.ChallengeID)
	if err != nil {
		return nil, err
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, challengeAppeal.OrganizationID)
	if err != nil {
		return nil, err
	}
	reconciliationBundle, err := s.BuildFederationIncidentDirectiveExtensionAppealReconciliationBundle(ctx, cellID, challengeAppeal.ComparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleOptions{})
	if err != nil {
		return nil, err
	}
	actions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter{
		CellID:            cellID,
		ChallengeAppealID: challengeAppealID,
	})
	if err != nil {
		return nil, err
	}
	alignmentActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionFilter{
		CellID:            cellID,
		ChallengeAppealID: challengeAppealID,
	})
	if err != nil {
		return nil, err
	}
	recusals, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalFilter{
		CellID:            cellID,
		ChallengeAppealID: challengeAppealID,
	})
	if err != nil {
		return nil, err
	}
	automationActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionFilter{
		CellID:            cellID,
		ChallengeAppealID: challengeAppealID,
	})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	bundle := &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle{
		ID:                           firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle", run.result.CellID, challengeAppealID)),
		Version:                      firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:                         firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Incident Directive Extension Appeal Reconciliation Challenge Appeal Bundle %s", challengeAppealID)),
		GeneratedAt:                  now,
		ExpiresAt:                    cloneTimePtr(&expiresAt),
		CellID:                       run.result.CellID,
		CellName:                     run.result.Name,
		CellStatus:                   run.result.Status,
		Jurisdiction:                 run.request.Jurisdiction,
		Framework:                    firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:                 orgSummary,
		Reconciliation:               reconciliation,
		ChallengeSummary:             challengeSummary,
		ChallengeAppealSummary:       *challengeAppeal,
		Actions:                      append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord(nil), actions...),
		CounterpartyAlignmentActions: append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionRecord(nil), alignmentActions...),
		Recusals:                     append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalSummary(nil), recusals...),
		AutomationActions:            append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionRecord(nil), automationActions...),
		ReconciliationBundleHash:     strings.TrimSpace(reconciliationBundle.ContentHash),
		Controls:                     secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces:             cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:                     cloneStringMap(options.Metadata),
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
	if s.config.FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSigner != nil {
		if err := s.config.FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSigner(ctx, bundle); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: external bundle signing failed: %w", err)
		}
	} else if err := SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

// VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle
// validates one signed challenge-appeal bundle.
func VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: bundle is required")
	}
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: signature verification failed")
	}
	return nil
}

// SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleEd25519
// signs one challenge-appeal bundle.
func SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleEd25519(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-bundle: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleDigest(bundle)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])

	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSignature{
		Algorithm: secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleSignatureAlgorithmED25519,
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleDigest(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle) [32]byte {
	clone := *bundle
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}
