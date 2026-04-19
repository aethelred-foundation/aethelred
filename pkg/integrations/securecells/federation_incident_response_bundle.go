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
)

const secureCellFederationIncidentResponseBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentResponseBundleSignature captures detached signer
// metadata for one portable response bundle.
type SecureCellFederationIncidentResponseBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentResponseBundle is the signed portable auditor
// package for one bilateral incident response.
type SecureCellFederationIncidentResponseBundle struct {
	ID                      string                                          `json:"id"`
	Version                 string                                          `json:"version"`
	Name                    string                                          `json:"name"`
	GeneratedAt             time.Time                                       `json:"generated_at"`
	ExpiresAt               *time.Time                                      `json:"expires_at,omitempty"`
	CellID                  string                                          `json:"cell_id"`
	CellName                string                                          `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                                `json:"cell_status"`
	Jurisdiction            string                                          `json:"jurisdiction,omitempty"`
	Framework               string                                          `json:"framework,omitempty"`
	Organization            SecureCellFederationOrganizationSummary         `json:"organization"`
	ResponseSummary         SecureCellFederationIncidentResponseSummary     `json:"response_summary"`
	Response                SecureCellFederationIncidentResponse            `json:"response"`
	Contracts               []SecureCellFederationContractSummary           `json:"contracts,omitempty"`
	Controls                []SecureCellFederationTrustPackControl          `json:"controls,omitempty"`
	OperatorSurfaces        []SecureCellFederationOperatorSurface           `json:"operator_surfaces,omitempty"`
	ControlLedgerID         string                                          `json:"control_ledger_id,omitempty"`
	ControlLedgerHash       string                                          `json:"control_ledger_hash,omitempty"`
	PortablePackageHash     string                                          `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                            `json:"portable_package_signed"`
	PortablePackageAnchored bool                                            `json:"portable_package_anchored"`
	ContentHash             string                                          `json:"content_hash,omitempty"`
	Signature               *SecureCellFederationIncidentResponseBundleSignature `json:"signature,omitempty"`
	Metadata                map[string]string                               `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentResponseBundleOptions lets callers tune bundle
// identity, expiry, and operator-surface hints.
type SecureCellFederationIncidentResponseBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

// BuildFederationIncidentResponseBundle returns the signed portable auditor
// bundle for one bilateral incident response.
func (s *Service) BuildFederationIncidentResponseBundle(ctx context.Context, cellID string, responseID string, options SecureCellFederationIncidentResponseBundleOptions) (*SecureCellFederationIncidentResponseBundle, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	responseSummary, response, err := secureCellFederationIncidentResponseSummaryAndRef(run, responseID)
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
		return nil, fmt.Errorf("securecells/federation-incident-response: failed to clone response %q", responseID)
	}
	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	bundle := &SecureCellFederationIncidentResponseBundle{
		ID:               firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-response-bundle", run.result.CellID, response.ID)),
		Version:          firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:             firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Incident Response Bundle %s", response.ID)),
		GeneratedAt:      now,
		ExpiresAt:        cloneTimePtr(&expiresAt),
		CellID:           run.result.CellID,
		CellName:         run.result.Name,
		CellStatus:       run.result.Status,
		Jurisdiction:     run.request.Jurisdiction,
		Framework:        firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:     orgSummary,
		ResponseSummary:  responseSummary,
		Response:         cloned.FederationIncidentResponses[0],
		Contracts:        secureCellFederationContractSummariesForResponse(run, *response),
		Controls:         secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces: cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:         cloneStringMap(options.Metadata),
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
	if s.config.FederationIncidentResponseBundleSigner != nil {
		if err := s.config.FederationIncidentResponseBundleSigner(ctx, bundle); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident-response: external response bundle signing failed: %w", err)
		}
	} else if err := SignFederationIncidentResponseBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

// VerifyFederationIncidentResponseBundle validates one signed response bundle.
func VerifyFederationIncidentResponseBundle(bundle *SecureCellFederationIncidentResponseBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-response: bundle is required")
	}
	digest := secureCellFederationIncidentResponseBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-response: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-response: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-response: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationIncidentResponseBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-response: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-response: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-response: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-response: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-response: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-response: signature verification failed")
	}
	return nil
}

// SignFederationIncidentResponseBundleEd25519 signs one response bundle.
func SignFederationIncidentResponseBundleEd25519(bundle *SecureCellFederationIncidentResponseBundle, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-response: bundle is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-response: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentResponseBundleDigest(bundle)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])

	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = &SecureCellFederationIncidentResponseBundleSignature{
		Algorithm: secureCellFederationIncidentResponseBundleSignatureAlgorithmED25519,
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

func secureCellFederationIncidentResponseBundleDigest(bundle *SecureCellFederationIncidentResponseBundle) [32]byte {
	clone := *bundle
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}

func secureCellFederationIncidentResponseSummaryAndRef(run *secureCellRun, responseID string) (SecureCellFederationIncidentResponseSummary, *SecureCellFederationIncidentResponse, error) {
	if run == nil || run.result == nil {
		return SecureCellFederationIncidentResponseSummary{}, nil, fmt.Errorf("securecells/federation-incident-response: secure cell result is required")
	}
	_, response := findSecureCellFederationIncidentResponse(run.result.FederationIncidentResponses, responseID)
	if response == nil {
		return SecureCellFederationIncidentResponseSummary{}, nil, fmt.Errorf("securecells/federation-incident-response: %w: %q", ErrFederationIncidentResponseNotFound, responseID)
	}
	return secureCellFederationIncidentResponseSummaryFromRun(run, *response), response, nil
}

func secureCellFederationContractSummariesForResponse(run *secureCellRun, response SecureCellFederationIncidentResponse) []SecureCellFederationContractSummary {
	if run == nil || run.result == nil {
		return nil
	}
	items := make([]SecureCellFederationContractSummary, 0)
	for _, contract := range run.result.FederationContracts {
		if strings.TrimSpace(contract.OrganizationID) != strings.TrimSpace(response.OrganizationID) {
			continue
		}
		if len(response.ContractIDs) > 0 && !secureCellStringSliceContains(response.ContractIDs, contract.ID) {
			continue
		}
		items = append(items, secureCellFederationContractSummaryFromRun(run, contract))
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	return items
}
