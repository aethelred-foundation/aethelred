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

const secureCellFederationIncidentDirectiveBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentDirectiveBundleSignature captures detached signer
// metadata for one portable incident directive bundle.
type SecureCellFederationIncidentDirectiveBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentDirectiveBundle is the signed portable auditor
// package for one bilateral incident directive or work order.
type SecureCellFederationIncidentDirectiveBundle struct {
	ID                         string                                                                 `json:"id"`
	Version                    string                                                                 `json:"version"`
	Name                       string                                                                 `json:"name"`
	GeneratedAt                time.Time                                                              `json:"generated_at"`
	ExpiresAt                  *time.Time                                                             `json:"expires_at,omitempty"`
	CellID                     string                                                                 `json:"cell_id"`
	CellName                   string                                                                 `json:"cell_name,omitempty"`
	CellStatus                 SecureCellStatus                                                       `json:"cell_status"`
	Jurisdiction               string                                                                 `json:"jurisdiction,omitempty"`
	Framework                  string                                                                 `json:"framework,omitempty"`
	Organization               SecureCellFederationOrganizationSummary                                `json:"organization"`
	ResponseSummary            SecureCellFederationIncidentResponseSummary                            `json:"response_summary"`
	DirectiveSummary           SecureCellFederationIncidentDirectiveSummary                           `json:"directive_summary"`
	Directive                  SecureCellFederationIncidentDirective                                  `json:"directive"`
	ExtensionSummaries         []SecureCellFederationIncidentDirectiveExtensionSummary                `json:"extension_summaries,omitempty"`
	ExtensionDisputes          []SecureCellFederationIncidentDirectiveExtensionDisputeSummary         `json:"extension_disputes,omitempty"`
	ExtensionAutomationActions []SecureCellFederationIncidentDirectiveExtensionAutomationActionRecord `json:"extension_automation_actions,omitempty"`
	ResponseBundleHash         string                                                                 `json:"response_bundle_hash,omitempty"`
	Contracts                  []SecureCellFederationContractSummary                                  `json:"contracts,omitempty"`
	Controls                   []SecureCellFederationTrustPackControl                                 `json:"controls,omitempty"`
	OperatorSurfaces           []SecureCellFederationOperatorSurface                                  `json:"operator_surfaces,omitempty"`
	ControlLedgerID            string                                                                 `json:"control_ledger_id,omitempty"`
	ControlLedgerHash          string                                                                 `json:"control_ledger_hash,omitempty"`
	PortablePackageHash        string                                                                 `json:"portable_package_hash,omitempty"`
	PortablePackageSigned      bool                                                                   `json:"portable_package_signed"`
	PortablePackageAnchored    bool                                                                   `json:"portable_package_anchored"`
	ContentHash                string                                                                 `json:"content_hash,omitempty"`
	Signature                  *SecureCellFederationIncidentDirectiveBundleSignature                  `json:"signature,omitempty"`
	Metadata                   map[string]string                                                      `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveBundleOptions lets callers tune bundle
// identity, expiry, and operator-surface hints.
type SecureCellFederationIncidentDirectiveBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

// BuildFederationIncidentDirectiveBundle returns the signed portable auditor
// bundle for one bilateral incident directive or work order.
func (s *Service) BuildFederationIncidentDirectiveBundle(ctx context.Context, cellID string, directiveID string, options SecureCellFederationIncidentDirectiveBundleOptions) (*SecureCellFederationIncidentDirectiveBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	directiveSummary, response, directive, err := secureCellFederationIncidentDirectiveSummaryAndRef(run, directiveID)
	if err != nil {
		return nil, err
	}
	orgSummary, _, err := secureCellFederationOrganizationSummaryAndRef(run, response.OrganizationID)
	if err != nil {
		return nil, err
	}
	cloned, err := cloneResult(&SecureCellResult{FederationIncidentResponses: []SecureCellFederationIncidentResponse{*response}})
	if err != nil {
		return nil, err
	}
	if cloned == nil || len(cloned.FederationIncidentResponses) == 0 {
		return nil, fmt.Errorf("securecells/federation-incident-directive: failed to clone directive response %q", directiveID)
	}
	_, _, _, clonedDirective := findSecureCellFederationIncidentDirective(cloned.FederationIncidentResponses, directiveID)
	if clonedDirective == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive: failed to clone directive %q", directiveID)
	}
	responseBundle, err := s.BuildFederationIncidentResponseBundle(ctx, cellID, response.ID, SecureCellFederationIncidentResponseBundleOptions{})
	if err != nil {
		return nil, err
	}
	extensionDisputes, err := s.ListFederationIncidentDirectiveExtensionDisputes(ctx, SecureCellFederationIncidentDirectiveExtensionDisputeFilter{
		CellID:      cellID,
		DirectiveID: directive.ID,
	})
	if err != nil {
		return nil, err
	}
	extensionSummaries, err := s.ListFederationIncidentDirectiveExtensions(ctx, SecureCellFederationIncidentDirectiveExtensionFilter{
		CellID:      cellID,
		DirectiveID: directive.ID,
	})
	if err != nil {
		return nil, err
	}
	extensionAutomationActions, err := s.ListFederationIncidentDirectiveExtensionAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAutomationActionFilter{
		CellID:      cellID,
		DirectiveID: directive.ID,
	})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	bundle := &SecureCellFederationIncidentDirectiveBundle{
		ID:                         firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-incident-directive-bundle", run.result.CellID, directive.ID)),
		Version:                    firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:                       firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Incident Directive Bundle %s", directive.ID)),
		GeneratedAt:                now,
		ExpiresAt:                  cloneTimePtr(&expiresAt),
		CellID:                     run.result.CellID,
		CellName:                   run.result.Name,
		CellStatus:                 run.result.Status,
		Jurisdiction:               run.request.Jurisdiction,
		Framework:                  firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:               orgSummary,
		ResponseSummary:            secureCellFederationIncidentResponseSummaryFromRun(run, *response),
		DirectiveSummary:           directiveSummary,
		Directive:                  *clonedDirective,
		ExtensionSummaries:         append([]SecureCellFederationIncidentDirectiveExtensionSummary(nil), extensionSummaries...),
		ExtensionDisputes:          append([]SecureCellFederationIncidentDirectiveExtensionDisputeSummary(nil), extensionDisputes...),
		ExtensionAutomationActions: append([]SecureCellFederationIncidentDirectiveExtensionAutomationActionRecord(nil), extensionAutomationActions...),
		ResponseBundleHash:         strings.TrimSpace(responseBundle.ContentHash),
		Contracts:                  secureCellFederationContractSummariesForResponse(run, *response),
		Controls:                   secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces:           cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:                   cloneStringMap(options.Metadata),
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
	if s.config.FederationIncidentDirectiveBundleSigner != nil {
		if err := s.config.FederationIncidentDirectiveBundleSigner(ctx, bundle); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident-directive: external directive bundle signing failed: %w", err)
		}
	} else if err := SignFederationIncidentDirectiveBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

// VerifyFederationIncidentDirectiveBundle validates one signed directive
// bundle.
func VerifyFederationIncidentDirectiveBundle(bundle *SecureCellFederationIncidentDirectiveBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive: bundle is required")
	}
	digest := secureCellFederationIncidentDirectiveBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-directive: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-directive: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-directive: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentDirectiveBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-directive: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-directive: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-directive: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-directive: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-directive: signature verification failed")
	}
	return nil
}

// SignFederationIncidentDirectiveBundleEd25519 signs one directive bundle.
func SignFederationIncidentDirectiveBundleEd25519(bundle *SecureCellFederationIncidentDirectiveBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-directive: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentDirectiveBundleDigest(bundle)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])

	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentDirectiveBundleSignature{
		Algorithm: secureCellFederationIncidentDirectiveBundleSignatureAlgorithmED25519,
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

func secureCellFederationIncidentDirectiveBundleDigest(bundle *SecureCellFederationIncidentDirectiveBundle) [32]byte {
	clone := *bundle
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}

func secureCellFederationIncidentDirectiveSummaryAndRef(run *secureCellRun, directiveID string) (SecureCellFederationIncidentDirectiveSummary, *SecureCellFederationIncidentResponse, *SecureCellFederationIncidentDirective, error) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentDirectiveSummary{}, nil, nil, fmt.Errorf("securecells/federation-incident-directive: secure cell result is required")
	}
	_, _, response, directive := findSecureCellFederationIncidentDirective(run.result.FederationIncidentResponses, directiveID)
	if response == nil || directive == nil {
		return SecureCellFederationIncidentDirectiveSummary{}, nil, nil, fmt.Errorf("securecells/federation-incident-directive: %w: %q", ErrFederationIncidentDirectiveNotFound, directiveID)
	}
	return secureCellFederationIncidentDirectiveSummaryFromRun(run, *response, *directive), response, directive, nil
}
