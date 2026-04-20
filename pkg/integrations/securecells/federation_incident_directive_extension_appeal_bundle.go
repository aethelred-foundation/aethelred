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

const secureCellFederationIncidentDirectiveExtensionAppealBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentDirectiveExtensionAppealBundleSignature captures
// detached signer metadata for one portable directive-exception appeal bundle.
type SecureCellFederationIncidentDirectiveExtensionAppealBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealBundle is the signed
// portable auditor package for one bilateral directive-exception appeal.
type SecureCellFederationIncidentDirectiveExtensionAppealBundle struct {
	ID                      string                                                                       `json:"id"`
	Version                 string                                                                       `json:"version"`
	Name                    string                                                                       `json:"name"`
	GeneratedAt             time.Time                                                                    `json:"generated_at"`
	ExpiresAt               *time.Time                                                                   `json:"expires_at,omitempty"`
	CellID                  string                                                                       `json:"cell_id"`
	CellName                string                                                                       `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                                                             `json:"cell_status"`
	Jurisdiction            string                                                                       `json:"jurisdiction,omitempty"`
	Framework               string                                                                       `json:"framework,omitempty"`
	Organization            SecureCellFederationOrganizationSummary                                      `json:"organization"`
	ResponseSummary         SecureCellFederationIncidentResponseSummary                                  `json:"response_summary"`
	DirectiveSummary        SecureCellFederationIncidentDirectiveSummary                                 `json:"directive_summary"`
	ExtensionSummary        SecureCellFederationIncidentDirectiveExtensionSummary                        `json:"extension_summary"`
	DisputeSummary          SecureCellFederationIncidentDirectiveExtensionDisputeSummary                 `json:"dispute_summary"`
	AppealSummary           SecureCellFederationIncidentDirectiveExtensionAppealSummary                  `json:"appeal_summary"`
	Appeal                  SecureCellFederationIncidentDirectiveExtensionAppeal                         `json:"appeal"`
	AutomationActions       []SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionRecord `json:"automation_actions,omitempty"`
	DirectiveBundleHash     string                                                                       `json:"directive_bundle_hash,omitempty"`
	Controls                []SecureCellFederationTrustPackControl                                       `json:"controls,omitempty"`
	OperatorSurfaces        []SecureCellFederationOperatorSurface                                        `json:"operator_surfaces,omitempty"`
	ControlLedgerID         string                                                                       `json:"control_ledger_id,omitempty"`
	ControlLedgerHash       string                                                                       `json:"control_ledger_hash,omitempty"`
	PortablePackageHash     string                                                                       `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                                                         `json:"portable_package_signed"`
	PortablePackageAnchored bool                                                                         `json:"portable_package_anchored"`
	ContentHash             string                                                                       `json:"content_hash,omitempty"`
	Signature               *SecureCellFederationIncidentDirectiveExtensionAppealBundleSignature         `json:"signature,omitempty"`
	Metadata                map[string]string                                                            `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealBundleOptions lets
// callers tune bundle identity, expiry, and operator-surface hints.
type SecureCellFederationIncidentDirectiveExtensionAppealBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

// BuildFederationIncidentDirectiveExtensionAppealBundle returns the signed
// portable auditor bundle for one directive-exception appeal.
func (s *Service) BuildFederationIncidentDirectiveExtensionAppealBundle(ctx context.Context, cellID string, appealID string, options SecureCellFederationIncidentDirectiveExtensionAppealBundleOptions) (*SecureCellFederationIncidentDirectiveExtensionAppealBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	responseIdx, directiveIdx, extensionIdx, disputeIdx, _, response, directive, extension, dispute, appeal := findSecureCellFederationIncidentDirectiveExtensionAppeal(run.result.FederationIncidentResponses, appealID)
	if response == nil || directive == nil || extension == nil || dispute == nil || appeal == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: %w: %q", ErrFederationIncidentDirectiveNotFound, appealID)
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, response.OrganizationID)
	if err != nil {
		return nil, err
	}
	directiveBundle, err := s.BuildFederationIncidentDirectiveBundle(ctx, cellID, directive.ID, SecureCellFederationIncidentDirectiveBundleOptions{})
	if err != nil {
		return nil, err
	}
	automationActions, err := s.ListFederationIncidentDirectiveExtensionAppealAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionFilter{
		CellID:   cellID,
		AppealID: appealID,
	})
	if err != nil {
		return nil, err
	}
	extensionSummary := secureCellFederationIncidentDirectiveExtensionSummaryFromRun(run, *response, *directive, *extension)
	disputeSummary := secureCellFederationIncidentDirectiveExtensionDisputeSummaryFromRun(run, *response, *directive, *extension, *dispute)
	appealSummary := secureCellFederationIncidentDirectiveExtensionAppealSummaryFromRun(run, *response, *directive, *extension, *dispute, *appeal)

	cloned, err := cloneResult(&SecureCellResult{FederationIncidentResponses: []SecureCellFederationIncidentResponse{*response}})
	if err != nil {
		return nil, err
	}
	if cloned == nil || len(cloned.FederationIncidentResponses) == 0 {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: failed to clone response %q", response.ID)
	}
	_, _, _, _, _, _, _, _, _, clonedAppeal := findSecureCellFederationIncidentDirectiveExtensionAppeal(cloned.FederationIncidentResponses, appealID)
	if clonedAppeal == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: failed to clone appeal %q", appealID)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	bundle := &SecureCellFederationIncidentDirectiveExtensionAppealBundle{
		ID:                  firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-incident-directive-extension-appeal-bundle", run.result.CellID, appealID)),
		Version:             firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:                firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Incident Directive Extension Appeal Bundle %s", appealID)),
		GeneratedAt:         now,
		ExpiresAt:           cloneTimePtr(&expiresAt),
		CellID:              run.result.CellID,
		CellName:            run.result.Name,
		CellStatus:          run.result.Status,
		Jurisdiction:        run.request.Jurisdiction,
		Framework:           firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:        orgSummary,
		ResponseSummary:     secureCellFederationIncidentResponseSummaryFromRun(run, *response),
		DirectiveSummary:    secureCellFederationIncidentDirectiveSummaryFromRun(run, *response, *directive),
		ExtensionSummary:    extensionSummary,
		DisputeSummary:      disputeSummary,
		AppealSummary:       appealSummary,
		Appeal:              *clonedAppeal,
		AutomationActions:   append([]SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionRecord(nil), automationActions...),
		DirectiveBundleHash: strings.TrimSpace(directiveBundle.ContentHash),
		Controls:            secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces:    cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:            cloneStringMap(options.Metadata),
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
	if s.config.FederationIncidentDirectiveExtensionAppealBundleSigner != nil {
		if err := s.config.FederationIncidentDirectiveExtensionAppealBundleSigner(ctx, bundle); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: external bundle signing failed: %w", err)
		}
	} else if err := SignFederationIncidentDirectiveExtensionAppealBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	_ = responseIdx
	_ = directiveIdx
	_ = extensionIdx
	_ = disputeIdx
	return bundle, nil
}

// VerifyFederationIncidentDirectiveExtensionAppealBundle validates one signed
// appeal bundle.
func VerifyFederationIncidentDirectiveExtensionAppealBundle(bundle *SecureCellFederationIncidentDirectiveExtensionAppealBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: bundle is required")
	}
	digest := secureCellFederationIncidentDirectiveExtensionAppealBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentDirectiveExtensionAppealBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: signature verification failed")
	}
	return nil
}

// SignFederationIncidentDirectiveExtensionAppealBundleEd25519 signs one appeal
// bundle.
func SignFederationIncidentDirectiveExtensionAppealBundleEd25519(bundle *SecureCellFederationIncidentDirectiveExtensionAppealBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-bundle: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentDirectiveExtensionAppealBundleDigest(bundle)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])

	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentDirectiveExtensionAppealBundleSignature{
		Algorithm: secureCellFederationIncidentDirectiveExtensionAppealBundleSignatureAlgorithmED25519,
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

func secureCellFederationIncidentDirectiveExtensionAppealBundleDigest(bundle *SecureCellFederationIncidentDirectiveExtensionAppealBundle) [32]byte {
	clone := *bundle
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}
