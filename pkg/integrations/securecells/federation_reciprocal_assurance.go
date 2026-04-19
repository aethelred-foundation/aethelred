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

const secureCellFederationAssuranceBundleSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationAssuranceBundleSignature captures the detached signer
// metadata for one portable federation assurance bundle.
type SecureCellFederationAssuranceBundleSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationAssuranceBundle is the signed portable posture package
// one collaborating organization can share with a counterparty.
type SecureCellFederationAssuranceBundle struct {
	ID                      string                                        `json:"id"`
	Version                 string                                        `json:"version"`
	Name                    string                                        `json:"name"`
	GeneratedAt             time.Time                                     `json:"generated_at"`
	ExpiresAt               *time.Time                                    `json:"expires_at,omitempty"`
	CellID                  string                                        `json:"cell_id"`
	CellName                string                                        `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                              `json:"cell_status"`
	Jurisdiction            string                                        `json:"jurisdiction,omitempty"`
	Framework               string                                        `json:"framework,omitempty"`
	Organization            SecureCellFederationOrganizationSummary       `json:"organization"`
	Runtime                 SecureCellFederationOrganizationRuntime       `json:"runtime"`
	Contracts               []SecureCellFederationContractSummary         `json:"contracts,omitempty"`
	Assurance               SecureCellFederationAssuranceReport           `json:"assurance"`
	OperatorSurfaces        []SecureCellFederationOperatorSurface         `json:"operator_surfaces,omitempty"`
	ControlLedgerID         string                                        `json:"control_ledger_id,omitempty"`
	ControlLedgerHash       string                                        `json:"control_ledger_hash,omitempty"`
	PortablePackageHash     string                                        `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                          `json:"portable_package_signed"`
	PortablePackageAnchored bool                                          `json:"portable_package_anchored"`
	ContentHash             string                                        `json:"content_hash,omitempty"`
	Signature               *SecureCellFederationAssuranceBundleSignature `json:"signature,omitempty"`
	Metadata                map[string]string                             `json:"metadata,omitempty"`
}

// SecureCellFederationAssuranceBundleOptions lets callers tune bundle
// identity, expiry, and operator-surface hints.
type SecureCellFederationAssuranceBundleOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

// SecureCellFederationCounterpartyAssuranceStatus tracks the freshness and
// verification posture of an imported counterparty assurance bundle.
type SecureCellFederationCounterpartyAssuranceStatus string

const (
	SecureCellFederationCounterpartyAssuranceStatusVerified SecureCellFederationCounterpartyAssuranceStatus = "verified"
	SecureCellFederationCounterpartyAssuranceStatusStale    SecureCellFederationCounterpartyAssuranceStatus = "stale"
	SecureCellFederationCounterpartyAssuranceStatusExpired  SecureCellFederationCounterpartyAssuranceStatus = "expired"
	SecureCellFederationCounterpartyAssuranceStatusInvalid  SecureCellFederationCounterpartyAssuranceStatus = "invalid"
)

// SecureCellFederationCounterpartyAssuranceSnapshot stores one imported
// counterparty assurance bundle inside the secure-cell runtime trace.
type SecureCellFederationCounterpartyAssuranceSnapshot struct {
	SnapshotID          string                                          `json:"snapshot_id"`
	OrganizationID      string                                          `json:"organization_id"`
	ContractIDs         []string                                        `json:"contract_ids,omitempty"`
	Bundle              SecureCellFederationAssuranceBundle             `json:"bundle"`
	Status              SecureCellFederationCounterpartyAssuranceStatus `json:"status"`
	Verified            bool                                            `json:"verified"`
	VerificationMessage string                                          `json:"verification_message,omitempty"`
	Signer              string                                          `json:"signer,omitempty"`
	ReceivedBy          string                                          `json:"received_by,omitempty"`
	ReceivedAt          time.Time                                       `json:"received_at"`
	Metadata            map[string]string                               `json:"metadata,omitempty"`
}

// SecureCellFederationCounterpartyAssuranceSummary is the operator-facing
// summary of one imported counterparty assurance snapshot.
type SecureCellFederationCounterpartyAssuranceSummary struct {
	CellID                  string                                          `json:"cell_id"`
	CellName                string                                          `json:"cell_name,omitempty"`
	CellStatus              SecureCellStatus                                `json:"cell_status"`
	Jurisdiction            string                                          `json:"jurisdiction,omitempty"`
	OrganizationID          string                                          `json:"organization_id"`
	SponsorOfRecord         string                                          `json:"sponsor_of_record,omitempty"`
	OrganizationName        string                                          `json:"organization_name,omitempty"`
	SnapshotID              string                                          `json:"snapshot_id"`
	BundleID                string                                          `json:"bundle_id,omitempty"`
	BundleVersion           string                                          `json:"bundle_version,omitempty"`
	BundleName              string                                          `json:"bundle_name,omitempty"`
	Status                  SecureCellFederationCounterpartyAssuranceStatus `json:"status"`
	Verified                bool                                            `json:"verified"`
	Signer                  string                                          `json:"signer,omitempty"`
	KeyID                   string                                          `json:"key_id,omitempty"`
	ContractIDs             []string                                        `json:"contract_ids,omitempty"`
	FindingCount            int                                             `json:"finding_count"`
	CriticalFindingCount    int                                             `json:"critical_finding_count"`
	WarningFindingCount     int                                             `json:"warning_finding_count"`
	InfoFindingCount        int                                             `json:"info_finding_count"`
	GeneratedAt             time.Time                                       `json:"generated_at,omitempty"`
	ExpiresAt               *time.Time                                      `json:"expires_at,omitempty"`
	ReceivedAt              time.Time                                       `json:"received_at,omitempty"`
	ControlLedgerID         string                                          `json:"control_ledger_id,omitempty"`
	ControlLedgerHash       string                                          `json:"control_ledger_hash,omitempty"`
	PortablePackageHash     string                                          `json:"portable_package_hash,omitempty"`
	PortablePackageSigned   bool                                            `json:"portable_package_signed"`
	PortablePackageAnchored bool                                            `json:"portable_package_anchored"`
	VerificationMessage     string                                          `json:"verification_message,omitempty"`
}

// SecureCellFederationCounterpartyAssuranceFilter narrows operator queries
// across imported reciprocal federation assurance snapshots.
type SecureCellFederationCounterpartyAssuranceFilter struct {
	CellID         string                                          `json:"cell_id,omitempty"`
	OrganizationID string                                          `json:"organization_id,omitempty"`
	ContractID     string                                          `json:"contract_id,omitempty"`
	Status         SecureCellFederationCounterpartyAssuranceStatus `json:"status,omitempty"`
	Signer         string                                          `json:"signer,omitempty"`
	Limit          int                                             `json:"limit,omitempty"`
}

// SecureCellFederationAssuranceIntakeRequest ingests one signed counterparty
// assurance bundle into the secure-cell evidence chain.
type SecureCellFederationAssuranceIntakeRequest struct {
	ActorDID string                               `json:"actor_did,omitempty"`
	Bundle   *SecureCellFederationAssuranceBundle `json:"bundle,omitempty"`
	Reason   string                               `json:"reason,omitempty"`
	Metadata map[string]string                    `json:"metadata,omitempty"`
}

// VerifyFederationAssuranceBundle validates one signed federation assurance
// bundle and returns an error if its content hash or signature is invalid.
func VerifyFederationAssuranceBundle(bundle *SecureCellFederationAssuranceBundle) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-assurance: bundle is required")
	}
	digest := secureCellFederationAssuranceBundleDigest(bundle)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(bundle.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-assurance: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-assurance: content hash mismatch")
	}
	if bundle.Signature == nil {
		return fmt.Errorf("securecells/federation-assurance: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(bundle.Signature.Algorithm)); algorithm != secureCellFederationAssuranceBundleSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-assurance: unsupported signature algorithm %q", bundle.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-assurance: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-assurance: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(bundle.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-assurance: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-assurance: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-assurance: signature verification failed")
	}
	return nil
}

// BuildFederationAssuranceBundle builds the signed portable assurance package
// for one collaborating organization in one secure cell.
func (s *Service) BuildFederationAssuranceBundle(ctx context.Context, cellID string, organizationID string, options SecureCellFederationAssuranceBundleOptions) (*SecureCellFederationAssuranceBundle, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	summary, org, err := secureCellFederationOrganizationSummaryAndRef(run, organizationID)
	if err != nil {
		return nil, err
	}
	report, err := s.BuildFederationAssuranceReport(ctx, cellID, organizationID, SecureCellFederationAssuranceReportOptions{
		OperatorSurfaces: append([]SecureCellFederationOperatorSurface(nil), options.OperatorSurfaces...),
	})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(48 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	bundle := &SecureCellFederationAssuranceBundle{
		ID:               firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-federation-assurance-bundle-%x", strings.TrimSpace(cellID), sha256.Sum256([]byte(strings.TrimSpace(organizationID))))),
		Version:          firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:             firstNonEmpty(strings.TrimSpace(options.Name), "Federation Assurance Bundle"),
		GeneratedAt:      now,
		ExpiresAt:        cloneTimePtr(&expiresAt),
		CellID:           strings.TrimSpace(run.result.CellID),
		CellName:         strings.TrimSpace(run.result.Name),
		CellStatus:       run.result.Status,
		Jurisdiction:     strings.TrimSpace(run.request.Jurisdiction),
		Framework:        firstNonEmpty(strings.TrimSpace(run.request.Policy.RetentionPolicy), strings.TrimSpace(s.config.Framework)),
		Organization:     summary,
		Runtime:          secureCellFederationRuntimeForOrganization(run, *org),
		Contracts:        secureCellFederationContractSummariesForOrganization(run, strings.TrimSpace(organizationID)),
		Assurance:        *report,
		OperatorSurfaces: append([]SecureCellFederationOperatorSurface(nil), options.OperatorSurfaces...),
		Metadata:         cloneStringMap(options.Metadata),
	}
	if len(bundle.OperatorSurfaces) == 0 {
		bundle.OperatorSurfaces = append([]SecureCellFederationOperatorSurface(nil), report.OperatorSurfaces...)
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
	if s.config.FederationAssuranceBundleSigner != nil {
		if err := s.config.FederationAssuranceBundleSigner(ctx, bundle); err != nil {
			return nil, fmt.Errorf("securecells/federation-assurance: external bundle signing failed: %w", err)
		}
	} else if err := SignFederationAssuranceBundleEd25519(bundle, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return bundle, nil
}

// IngestFederationAssuranceBundle imports one counterparty assurance bundle
// and binds it into the secure-cell evidence chain.
func (s *Service) IngestFederationAssuranceBundle(ctx context.Context, cellID string, organizationID string, intake SecureCellFederationAssuranceIntakeRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, org, err := secureCellFederationOrganizationSummaryAndRef(run, organizationID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(org.OrganizationID) == "" {
		return nil, fmt.Errorf("securecells/federation-assurance: %w: %q", ErrFederationOrganizationNotFound, organizationID)
	}
	if intake.Bundle == nil {
		return nil, fmt.Errorf("securecells/federation-assurance: bundle is required")
	}
	bundle := secureCellCloneFederationAssuranceBundle(*intake.Bundle)
	if strings.TrimSpace(bundle.Organization.OrganizationID) == "" {
		bundle.Organization.OrganizationID = strings.TrimSpace(summary.OrganizationID)
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.Organization.OrganizationID), strings.TrimSpace(summary.OrganizationID)) {
		return nil, fmt.Errorf("securecells/federation-assurance: bundle organization %q does not match target organization %q", bundle.Organization.OrganizationID, summary.OrganizationID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(intake.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/service: %w: actor %q is not permitted to intake federation assurance", ErrPolicyDenied, actorDID)
	}
	verificationErr := VerifyFederationAssuranceBundle(&bundle)
	status, verificationMessage, verified := secureCellFederationCounterpartyAssuranceStatusAt(&bundle, verificationErr, time.Now().UTC())
	contractIDs := secureCellFederationContractIDs(bundle.Contracts)

	receipt, err := s.evaluateStage(ctx, run.request, "intake_federation_assurance", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                          strings.TrimSpace(summary.OrganizationID),
		"federation_sponsor_of_record":                        strings.TrimSpace(summary.SponsorOfRecord),
		"federation_counterparty_assurance_bundle_id":         strings.TrimSpace(bundle.ID),
		"federation_counterparty_assurance_status":            string(status),
		"federation_counterparty_assurance_signer":            strings.TrimSpace(bundleSigner(&bundle)),
		"federation_counterparty_assurance_contract_ids":      strings.Join(contractIDs, ","),
		"federation_counterparty_assurance_findings":          fmt.Sprintf("%d", bundle.Assurance.FindingCount),
		"federation_counterparty_assurance_critical_findings": fmt.Sprintf("%d", bundle.Assurance.CriticalFindingCount),
		"cell_status_before":                                  string(run.result.Status),
		"transition_reason":                                   strings.TrimSpace(intake.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/service: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	snapshot := SecureCellFederationCounterpartyAssuranceSnapshot{
		SnapshotID:          fmt.Sprintf("%s-federation-counterparty-assurance-%x", strings.TrimSpace(cellID), sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", strings.TrimSpace(summary.OrganizationID), strings.TrimSpace(bundle.ID), now.Format(time.RFC3339Nano))))),
		OrganizationID:      strings.TrimSpace(summary.OrganizationID),
		ContractIDs:         append([]string(nil), contractIDs...),
		Bundle:              bundle,
		Status:              status,
		Verified:            verified,
		VerificationMessage: strings.TrimSpace(verificationMessage),
		Signer:              strings.TrimSpace(bundleSigner(&bundle)),
		ReceivedBy:          strings.TrimSpace(actorDID),
		ReceivedAt:          now,
		Metadata:            cloneStringMap(intake.Metadata),
	}
	run.result.FederationCounterpartyAssurance = append(run.result.FederationCounterpartyAssurance, snapshot)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_assurance_ingested", snapshot.SnapshotID),
		Action:           "secure_cell.federation_assurance_ingested",
		Actor:            actorDID,
		TargetType:       "federation_assurance",
		TargetDID:        snapshot.SnapshotID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(intake.Reason),
		Metadata: mergeStringMaps(intake.Metadata, map[string]string{
			"federation_organization_id":                             strings.TrimSpace(summary.OrganizationID),
			"federation_sponsor_of_record":                           strings.TrimSpace(summary.SponsorOfRecord),
			"federation_contract_id":                                 strings.Join(contractIDs, ","),
			"federation_counterparty_assurance_snapshot_id":          snapshot.SnapshotID,
			"federation_counterparty_assurance_bundle_id":            strings.TrimSpace(bundle.ID),
			"federation_counterparty_assurance_status":               string(snapshot.Status),
			"federation_counterparty_assurance_verified":             fmt.Sprintf("%t", snapshot.Verified),
			"federation_counterparty_assurance_signer":               snapshot.Signer,
			"federation_counterparty_assurance_findings":             fmt.Sprintf("%d", bundle.Assurance.FindingCount),
			"federation_counterparty_assurance_critical_findings":    fmt.Sprintf("%d", bundle.Assurance.CriticalFindingCount),
			"federation_counterparty_assurance_generated_at":         bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			"federation_counterparty_assurance_expires_at":           safeTimeString(bundle.ExpiresAt),
			"federation_counterparty_assurance_content_hash":         strings.TrimSpace(bundle.ContentHash),
			"federation_counterparty_assurance_verification_message": snapshot.VerificationMessage,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// ListFederationCounterpartyAssurance returns operator-facing summaries across
// imported counterparty assurance bundles.
func (s *Service) ListFederationCounterpartyAssurance(_ context.Context, filter SecureCellFederationCounterpartyAssuranceFilter) ([]SecureCellFederationCounterpartyAssuranceSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var items []SecureCellFederationCounterpartyAssuranceSummary
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, snapshot := range run.result.FederationCounterpartyAssurance {
			summary := secureCellFederationCounterpartyAssuranceSummaryFromRun(run, snapshot)
			if !matchesSecureCellFederationCounterpartyAssuranceFilter(summary, filter) {
				continue
			}
			items = append(items, summary)
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

func secureCellFederationContractSummariesForOrganization(run *secureCellRun, organizationID string) []SecureCellFederationContractSummary {
	if run == nil || run.result == nil {
		return nil
	}
	items := make([]SecureCellFederationContractSummary, 0)
	for _, contract := range run.result.FederationContracts {
		if strings.TrimSpace(contract.OrganizationID) != strings.TrimSpace(organizationID) {
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

func secureCellFederationCounterpartyAssuranceSummaryFromRun(run *secureCellRun, snapshot SecureCellFederationCounterpartyAssuranceSnapshot) SecureCellFederationCounterpartyAssuranceSummary {
	orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(snapshot.OrganizationID))
	summary := SecureCellFederationCounterpartyAssuranceSummary{
		CellID:                  safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:              safeSecureCellStatus(run),
		Jurisdiction:            safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:          strings.TrimSpace(snapshot.OrganizationID),
		SponsorOfRecord:         strings.TrimSpace(orgSummary.SponsorOfRecord),
		OrganizationName:        strings.TrimSpace(orgSummary.OrganizationName),
		SnapshotID:              strings.TrimSpace(snapshot.SnapshotID),
		BundleID:                strings.TrimSpace(snapshot.Bundle.ID),
		BundleVersion:           strings.TrimSpace(snapshot.Bundle.Version),
		BundleName:              strings.TrimSpace(snapshot.Bundle.Name),
		Status:                  snapshot.Status,
		Verified:                snapshot.Verified,
		Signer:                  strings.TrimSpace(snapshot.Signer),
		ContractIDs:             append([]string(nil), uniqueTrimmedStrings(snapshot.ContractIDs)...),
		FindingCount:            snapshot.Bundle.Assurance.FindingCount,
		CriticalFindingCount:    snapshot.Bundle.Assurance.CriticalFindingCount,
		WarningFindingCount:     snapshot.Bundle.Assurance.WarningFindingCount,
		InfoFindingCount:        snapshot.Bundle.Assurance.InfoFindingCount,
		GeneratedAt:             snapshot.Bundle.GeneratedAt.UTC(),
		ExpiresAt:               cloneTimePtr(snapshot.Bundle.ExpiresAt),
		ReceivedAt:              snapshot.ReceivedAt.UTC(),
		ControlLedgerID:         strings.TrimSpace(snapshot.Bundle.ControlLedgerID),
		ControlLedgerHash:       strings.TrimSpace(snapshot.Bundle.ControlLedgerHash),
		PortablePackageHash:     strings.TrimSpace(snapshot.Bundle.PortablePackageHash),
		PortablePackageSigned:   snapshot.Bundle.PortablePackageSigned,
		PortablePackageAnchored: snapshot.Bundle.PortablePackageAnchored,
		VerificationMessage:     strings.TrimSpace(snapshot.VerificationMessage),
	}
	if snapshot.Bundle.Signature != nil {
		summary.KeyID = strings.TrimSpace(snapshot.Bundle.Signature.KeyID)
	}
	return summary
}

func matchesSecureCellFederationCounterpartyAssuranceFilter(item SecureCellFederationCounterpartyAssuranceSummary, filter SecureCellFederationCounterpartyAssuranceFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.ContractID != "" {
		match := false
		for _, contractID := range item.ContractIDs {
			if strings.EqualFold(strings.TrimSpace(contractID), strings.TrimSpace(filter.ContractID)) {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.Signer != "" && !strings.EqualFold(strings.TrimSpace(item.Signer), strings.TrimSpace(filter.Signer)) {
		return false
	}
	return true
}

func secureCellFederationCounterpartyAssuranceByStatus(items []SecureCellFederationCounterpartyAssuranceSnapshot, status SecureCellFederationCounterpartyAssuranceStatus) []SecureCellFederationCounterpartyAssuranceSnapshot {
	if len(items) == 0 {
		return nil
	}
	out := make([]SecureCellFederationCounterpartyAssuranceSnapshot, 0, len(items))
	for _, item := range items {
		if item.Status == status {
			out = append(out, item)
		}
	}
	return out
}

func secureCellLatestFederationCounterpartyAssurance(result *SecureCellResult, organizationID string) *SecureCellFederationCounterpartyAssuranceSnapshot {
	if result == nil {
		return nil
	}
	var latest *SecureCellFederationCounterpartyAssuranceSnapshot
	for idx := range result.FederationCounterpartyAssurance {
		item := &result.FederationCounterpartyAssurance[idx]
		if !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(organizationID)) {
			continue
		}
		if latest == nil || item.ReceivedAt.After(latest.ReceivedAt) {
			latest = item
		}
	}
	return latest
}

func secureCellFederationCounterpartyAssuranceStatusAt(bundle *SecureCellFederationAssuranceBundle, verificationErr error, now time.Time) (SecureCellFederationCounterpartyAssuranceStatus, string, bool) {
	now = now.UTC()
	if verificationErr != nil {
		return SecureCellFederationCounterpartyAssuranceStatusInvalid, verificationErr.Error(), false
	}
	if bundle == nil {
		return SecureCellFederationCounterpartyAssuranceStatusInvalid, "bundle is required", false
	}
	if bundle.ExpiresAt != nil && !bundle.ExpiresAt.IsZero() && now.After(bundle.ExpiresAt.UTC()) {
		return SecureCellFederationCounterpartyAssuranceStatusExpired, "counterparty assurance bundle expired", true
	}
	if secureCellFederationAssuranceBundleIsStale(bundle, now) {
		return SecureCellFederationCounterpartyAssuranceStatusStale, "counterparty assurance bundle is stale", true
	}
	return SecureCellFederationCounterpartyAssuranceStatusVerified, "counterparty assurance bundle verified", true
}

func secureCellFederationAssuranceBundleIsStale(bundle *SecureCellFederationAssuranceBundle, now time.Time) bool {
	if bundle == nil || bundle.GeneratedAt.IsZero() {
		return false
	}
	now = now.UTC()
	staleAt := bundle.GeneratedAt.UTC().Add(24 * time.Hour)
	if bundle.ExpiresAt != nil && !bundle.ExpiresAt.IsZero() && bundle.ExpiresAt.UTC().Before(staleAt) {
		staleAt = bundle.ExpiresAt.UTC()
	}
	if bundle.ExpiresAt != nil && !bundle.ExpiresAt.IsZero() && now.After(bundle.ExpiresAt.UTC()) {
		return false
	}
	return now.After(staleAt)
}

// SignFederationAssuranceBundleEd25519 signs one federation assurance bundle
// in-place using an ed25519 private key and optional verification-key export.
func SignFederationAssuranceBundleEd25519(bundle *SecureCellFederationAssuranceBundle, signingKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-assurance: bundle is required")
	}
	digest := secureCellFederationAssuranceBundleDigest(bundle)
	bundle.ContentHash = hex.EncodeToString(digest[:])
	bundle.Signature = nil
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil
	}
	publicKey, ok := signingKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-assurance: invalid signing key")
	}
	signature := &SecureCellFederationAssuranceBundleSignature{
		Algorithm: secureCellFederationAssuranceBundleSignatureAlgorithmED25519,
		Signer:    strings.TrimSpace(signer),
		KeyID:     secureCellFederationAssuranceBundleKeyID(publicKey),
		Signature: hex.EncodeToString(ed25519.Sign(signingKey, digest[:])),
		SignedAt:  time.Now().UTC(),
	}
	if includeVerificationKeys {
		signature.PublicKey = hex.EncodeToString(publicKey)
	}
	bundle.Signature = signature
	return nil
}

func secureCellFederationAssuranceBundleKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

func secureCellFederationAssuranceBundleDigest(bundle *SecureCellFederationAssuranceBundle) [32]byte {
	if bundle == nil {
		return sha256.Sum256(nil)
	}
	canonical := *bundle
	canonical.ContentHash = ""
	canonical.Signature = nil
	return sha256.Sum256(mustJSON(canonical))
}

func secureCellCloneFederationAssuranceBundle(in SecureCellFederationAssuranceBundle) SecureCellFederationAssuranceBundle {
	data, _ := json.Marshal(in)
	var out SecureCellFederationAssuranceBundle
	_ = json.Unmarshal(data, &out)
	return out
}

func secureCellFederationContractIDs(items []SecureCellFederationContractSummary) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if contractID := strings.TrimSpace(item.ContractID); contractID != "" {
			out = append(out, contractID)
		}
	}
	return uniqueTrimmedStrings(out)
}

func bundleSigner(bundle *SecureCellFederationAssuranceBundle) string {
	if bundle == nil || bundle.Signature == nil {
		return ""
	}
	return strings.TrimSpace(bundle.Signature.Signer)
}
