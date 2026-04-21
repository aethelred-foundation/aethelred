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

const secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSignature
// captures detached signer metadata for one portable alignment response bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle
// is the signed auditor-facing package for one bilateral response to an
// automated reciprocal challenge-appeal alignment action.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle struct {
	ID                                     string                                                                                                                 `json:"id"`
	Version                                string                                                                                                                 `json:"version"`
	Name                                   string                                                                                                                 `json:"name"`
	GeneratedAt                            time.Time                                                                                                              `json:"generated_at"`
	ExpiresAt                              *time.Time                                                                                                             `json:"expires_at,omitempty"`
	CellID                                 string                                                                                                                 `json:"cell_id"`
	CellName                               string                                                                                                                 `json:"cell_name,omitempty"`
	CellStatus                             SecureCellStatus                                                                                                       `json:"cell_status"`
	Jurisdiction                           string                                                                                                                 `json:"jurisdiction,omitempty"`
	Framework                              string                                                                                                                 `json:"framework,omitempty"`
	Organization                           SecureCellFederationOrganizationSummary                                                                                `json:"organization"`
	ChallengeAppealSummary                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary                               `json:"challenge_appeal_summary"`
	CounterpartyChallengeAppeal            *SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary                  `json:"counterparty_challenge_appeal,omitempty"`
	ResponseStatus                         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus               `json:"response_status"`
	ResponseActionCount                    int                                                                                                                    `json:"response_action_count"`
	ResponseAppealCount                    int                                                                                                                    `json:"response_appeal_count"`
	ResponseAppealStatus                   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus         `json:"response_appeal_status,omitempty"`
	CounterpartyAlignmentActions           []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionRecord               `json:"counterparty_alignment_actions,omitempty"`
	CounterpartyAlignmentAutomationActions []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionRecord     `json:"counterparty_alignment_automation_actions,omitempty"`
	ResponseActions                        []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionRecord       `json:"response_actions,omitempty"`
	ResponseAppeals                        []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary      `json:"response_appeals,omitempty"`
	ResponseAppealActions                  []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord `json:"response_appeal_actions,omitempty"`
	ChallengeAppealBundleHash              string                                                                                                                 `json:"challenge_appeal_bundle_hash,omitempty"`
	Controls                               []SecureCellFederationTrustPackControl                                                                                 `json:"controls,omitempty"`
	OperatorSurfaces                       []SecureCellFederationOperatorSurface                                                                                  `json:"operator_surfaces,omitempty"`
	ControlLedgerID                        string                                                                                                                 `json:"control_ledger_id,omitempty"`
	ControlLedgerHash                      string                                                                                                                 `json:"control_ledger_hash,omitempty"`
	PortablePackageHash                    string                                                                                                                 `json:"portable_package_hash,omitempty"`
	PortablePackageSigned                  bool                                                                                                                   `json:"portable_package_signed"`
	PortablePackageAnchored                bool                                                                                                                   `json:"portable_package_anchored"`
	ContentHash                            string                                                                                                                 `json:"content_hash,omitempty"`
	Signature                              *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSignature     `json:"signature,omitempty"`
	Metadata                               map[string]string                                                                                                      `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleOptions
// lets callers tune bundle identity, expiry, and operator-surface hints.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

// BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle
// returns the signed auditor bundle for one bilateral automated-alignment
// response path.
func (s *Service) BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle(ctx context.Context, cellID string, challengeAppealID string, options SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleOptions) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	challengeAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealByID(run, challengeAppealID)
	if err != nil {
		return nil, err
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, challengeAppeal.OrganizationID)
	if err != nil {
		return nil, err
	}
	challengeAppealBundle, err := s.BuildFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundle(ctx, cellID, challengeAppealID, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBundleOptions{})
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
	alignmentAutomationActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionFilter{
		CellID:            cellID,
		ChallengeAppealID: challengeAppealID,
	})
	if err != nil {
		return nil, err
	}
	responseActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionFilter{
		CellID:            cellID,
		ChallengeAppealID: challengeAppealID,
	})
	if err != nil {
		return nil, err
	}
	responseAppeals, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealFilter{
		CellID:            cellID,
		ChallengeAppealID: challengeAppealID,
	})
	if err != nil {
		return nil, err
	}
	responseAppealActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter{
		CellID:            cellID,
		ChallengeAppealID: challengeAppealID,
	})
	if err != nil {
		return nil, err
	}

	var counterpartyChallengeAppeal *SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary
	if latest, err := secureCellLatestCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealByChallengeAppealID(run, challengeAppealID); err == nil && latest != nil {
		copy := *latest
		counterpartyChallengeAppeal = &copy
	}
	responseStatus := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusUnreviewed
	if latest := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAction(run, challengeAppealID); latest != nil {
		responseStatus = latest.ResponseStatus
	}
	responseAppealStatus := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus("")
	if len(responseAppeals) > 0 {
		responseAppealStatus = responseAppeals[0].Status
	}

	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	bundle := &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle{
		ID:                                     firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle", run.result.CellID, challengeAppealID)),
		Version:                                firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:                                   firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Incident Directive Extension Appeal Reconciliation Challenge Appeal Alignment Response Bundle %s", challengeAppealID)),
		GeneratedAt:                            now,
		ExpiresAt:                              cloneTimePtr(&expiresAt),
		CellID:                                 run.result.CellID,
		CellName:                               run.result.Name,
		CellStatus:                             run.result.Status,
		Jurisdiction:                           run.request.Jurisdiction,
		Framework:                              firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:                           orgSummary,
		ChallengeAppealSummary:                 *challengeAppeal,
		CounterpartyChallengeAppeal:            counterpartyChallengeAppeal,
		ResponseStatus:                         responseStatus,
		ResponseActionCount:                    len(responseActions),
		ResponseAppealCount:                    len(responseAppeals),
		ResponseAppealStatus:                   responseAppealStatus,
		CounterpartyAlignmentActions:           append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentActionRecord(nil), alignmentActions...),
		CounterpartyAlignmentAutomationActions: append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionRecord(nil), alignmentAutomationActions...),
		ResponseActions:                        append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionRecord(nil), responseActions...),
		ResponseAppeals:                        append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary(nil), responseAppeals...),
		ResponseAppealActions:                  append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord(nil), responseAppealActions...),
		ChallengeAppealBundleHash:              strings.TrimSpace(challengeAppealBundle.ContentHash),
		Controls:                               secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces:                       cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:                               cloneStringMap(options.Metadata),
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
	if s.config.FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSigner != nil {
		if err := s.config.FederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSigner(ctx, bundle); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: external bundle signing failed: %w", err)
		}
	} else if err := SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

// VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle
// validates one signed alignment-response bundle.
func VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: bundle is required")
	}
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: signature verification failed")
	}
	return nil
}

// SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleEd25519
// signs one alignment-response bundle.
func SignFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleEd25519(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-bundle: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleDigest(bundle)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])

	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSignature{
		Algorithm: secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSignatureAlgorithmED25519,
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleDigest(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle) [32]byte {
	clone := *bundle
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}
