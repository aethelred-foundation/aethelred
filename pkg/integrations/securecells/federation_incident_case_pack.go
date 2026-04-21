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

const secureCellFederationIncidentCasePackSignatureAlgorithmED25519 = "ed25519"

// SecureCellFederationIncidentCasePackSignature captures detached signer metadata
// for one portable incident case pack.
type SecureCellFederationIncidentCasePackSignature struct {
	Algorithm string    `json:"algorithm"`
	Signer    string    `json:"signer,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	PublicKey string    `json:"public_key,omitempty"`
	Signature string    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at"`
}

// SecureCellFederationIncidentCasePack is the signed portable bilateral incident
// package for one response, including filings, amendments, reconciliations, and
// command evidence.
type SecureCellFederationIncidentCasePack struct {
	ID                                                               string                                                                                              `json:"id"`
	Version                                                          string                                                                                              `json:"version"`
	Name                                                             string                                                                                              `json:"name"`
	GeneratedAt                                                      time.Time                                                                                           `json:"generated_at"`
	ExpiresAt                                                        *time.Time                                                                                          `json:"expires_at,omitempty"`
	CellID                                                           string                                                                                              `json:"cell_id"`
	CellName                                                         string                                                                                              `json:"cell_name,omitempty"`
	CellStatus                                                       SecureCellStatus                                                                                    `json:"cell_status"`
	Jurisdiction                                                     string                                                                                              `json:"jurisdiction,omitempty"`
	Framework                                                        string                                                                                              `json:"framework,omitempty"`
	Organization                                                     SecureCellFederationOrganizationSummary                                                             `json:"organization"`
	ResponseSummary                                                  SecureCellFederationIncidentResponseSummary                                                         `json:"response_summary"`
	ResponseBundle                                                   *SecureCellFederationIncidentResponseBundle                                                         `json:"response_bundle,omitempty"`
	DirectiveBundles                                                 []*SecureCellFederationIncidentDirectiveBundle                                                      `json:"directive_bundles,omitempty"`
	DirectiveExtensionSummaries                                      []SecureCellFederationIncidentDirectiveExtensionSummary                                             `json:"directive_extension_summaries,omitempty"`
	DirectiveExtensionAppealBundles                                  []*SecureCellFederationIncidentDirectiveExtensionAppealBundle                                       `json:"directive_extension_appeal_bundles,omitempty"`
	DirectiveExtensionAppealReconciliationBundles                    []*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle                         `json:"directive_extension_appeal_reconciliation_bundles,omitempty"`
	DirectiveExtensionAppealReconciliationChallenges                 []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary                `json:"directive_extension_appeal_reconciliation_challenges,omitempty"`
	DirectiveExtensionAppealReconciliationChallengeAppeals           []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary          `json:"directive_extension_appeal_reconciliation_challenge_appeals,omitempty"`
	ReportBundles                                                    []*SecureCellFederationIncidentReportBundle                                                         `json:"report_bundles,omitempty"`
	AmendmentBundles                                                 []*SecureCellFederationIncidentReportAmendmentBundle                                                `json:"amendment_bundles,omitempty"`
	ReportReconciliationBundles                                      []*SecureCellFederationIncidentReportReconciliationBundle                                           `json:"report_reconciliation_bundles,omitempty"`
	AmendmentReconciliationBundles                                   []*SecureCellFederationIncidentReportAmendmentReconciliationBundle                                  `json:"amendment_reconciliation_bundles,omitempty"`
	ResponseActions                                                  []SecureCellFederationIncidentResponseActionRecord                                                  `json:"response_actions,omitempty"`
	DirectiveAutomationActions                                       []SecureCellFederationIncidentDirectiveAutomationActionRecord                                       `json:"directive_automation_actions,omitempty"`
	DirectiveExtensionDisputes                                       []SecureCellFederationIncidentDirectiveExtensionDisputeSummary                                      `json:"directive_extension_disputes,omitempty"`
	DirectiveExtensionAppealAutomationActions                        []SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionRecord                        `json:"directive_extension_appeal_automation_actions,omitempty"`
	DirectiveExtensionAppealReconciliationAutomationActions          []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionRecord          `json:"directive_extension_appeal_reconciliation_automation_actions,omitempty"`
	DirectiveExtensionAppealReconciliationChallengeAutomationActions []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionRecord `json:"directive_extension_appeal_reconciliation_challenge_automation_actions,omitempty"`
	DirectiveExtensionAppealReconciliationChallengeActions           []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord           `json:"directive_extension_appeal_reconciliation_challenge_actions,omitempty"`
	DirectiveExtensionAppealReconciliationChallengeAppealActions     []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord     `json:"directive_extension_appeal_reconciliation_challenge_appeal_actions,omitempty"`
	DirectiveExtensionAutomationActions                              []SecureCellFederationIncidentDirectiveExtensionAutomationActionRecord                              `json:"directive_extension_automation_actions,omitempty"`
	Remediations                                                     []SecureCellFederationIncidentRemediationSummary                                                    `json:"remediations,omitempty"`
	Verifications                                                    []SecureCellFederationIncidentVerificationSummary                                                   `json:"verifications,omitempty"`
	Closures                                                         []SecureCellFederationIncidentClosureAttestationSummary                                             `json:"closures,omitempty"`
	Disputes                                                         []SecureCellFederationIncidentDisputeSummary                                                        `json:"disputes,omitempty"`
	ReportReconciliationAutomationActions                            []SecureCellFederationIncidentReportReconciliationAutomationActionRecord                            `json:"report_reconciliation_automation_actions,omitempty"`
	AmendmentReconciliationAttestations                              []SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationRecord            `json:"amendment_reconciliation_attestations,omitempty"`
	AmendmentReconciliationAutomationActions                         []SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionRecord                   `json:"amendment_reconciliation_automation_actions,omitempty"`
	Controls                                                         []SecureCellFederationTrustPackControl                                                              `json:"controls,omitempty"`
	OperatorSurfaces                                                 []SecureCellFederationOperatorSurface                                                               `json:"operator_surfaces,omitempty"`
	ControlLedgerID                                                  string                                                                                              `json:"control_ledger_id,omitempty"`
	ControlLedgerHash                                                string                                                                                              `json:"control_ledger_hash,omitempty"`
	PortablePackageHash                                              string                                                                                              `json:"portable_package_hash,omitempty"`
	PortablePackageSigned                                            bool                                                                                                `json:"portable_package_signed"`
	PortablePackageAnchored                                          bool                                                                                                `json:"portable_package_anchored"`
	ContentHash                                                      string                                                                                              `json:"content_hash,omitempty"`
	Signature                                                        *SecureCellFederationIncidentCasePackSignature                                                      `json:"signature,omitempty"`
	Metadata                                                         map[string]string                                                                                   `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentCasePackOptions lets callers tune case-pack
// identity, expiry, and operator-surface hints.
type SecureCellFederationIncidentCasePackOptions struct {
	ID               string                                `json:"id,omitempty"`
	Version          string                                `json:"version,omitempty"`
	Name             string                                `json:"name,omitempty"`
	ExpiresAfter     time.Duration                         `json:"expires_after,omitempty"`
	OperatorSurfaces []SecureCellFederationOperatorSurface `json:"operator_surfaces,omitempty"`
	Metadata         map[string]string                     `json:"metadata,omitempty"`
}

// BuildFederationIncidentCasePack returns the signed portable bilateral case
// package for one incident response.
func (s *Service) BuildFederationIncidentCasePack(ctx context.Context, cellID string, responseID string, options SecureCellFederationIncidentCasePackOptions) (*SecureCellFederationIncidentCasePack, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-case-pack: service is required")
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

	responseBundle, err := s.BuildFederationIncidentResponseBundle(ctx, cellID, responseID, SecureCellFederationIncidentResponseBundleOptions{})
	if err != nil {
		return nil, err
	}

	directiveBundles := make([]*SecureCellFederationIncidentDirectiveBundle, 0, len(response.IncidentDirectives))
	directiveExtensionSummaries := make([]SecureCellFederationIncidentDirectiveExtensionSummary, 0)
	directiveExtensionAppealBundles := make([]*SecureCellFederationIncidentDirectiveExtensionAppealBundle, 0)
	directiveExtensionAppealReconciliationBundles := make([]*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundle, 0)
	directiveExtensionAppealReconciliationChallenges := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary, 0)
	directiveExtensionAppealReconciliationChallengeAppeals := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, 0)
	for _, directive := range response.IncidentDirectives {
		directiveBundle, err := s.BuildFederationIncidentDirectiveBundle(ctx, cellID, directive.ID, SecureCellFederationIncidentDirectiveBundleOptions{})
		if err != nil {
			return nil, err
		}
		directiveBundles = append(directiveBundles, directiveBundle)
		if directiveBundle != nil {
			directiveExtensionSummaries = append(directiveExtensionSummaries, directiveBundle.ExtensionSummaries...)
			for _, appeal := range directiveBundle.ExtensionAppeals {
				appealBundle, err := s.BuildFederationIncidentDirectiveExtensionAppealBundle(ctx, cellID, appeal.AppealID, SecureCellFederationIncidentDirectiveExtensionAppealBundleOptions{})
				if err != nil {
					return nil, err
				}
				directiveExtensionAppealBundles = append(directiveExtensionAppealBundles, appealBundle)
			}
		}
	}
	directiveExtensionAppealReconciliations, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliations(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationFilter{
		CellID:         cellID,
		OrganizationID: response.OrganizationID,
		ResponseID:     responseID,
	})
	if err != nil {
		return nil, err
	}
	for _, reconciliation := range directiveExtensionAppealReconciliations {
		reconciliationBundle, err := s.BuildFederationIncidentDirectiveExtensionAppealReconciliationBundle(ctx, cellID, reconciliation.ComparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationBundleOptions{})
		if err != nil {
			return nil, err
		}
		directiveExtensionAppealReconciliationBundles = append(directiveExtensionAppealReconciliationBundles, reconciliationBundle)
	}
	directiveExtensionAppealReconciliationChallenges, err = s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallenges(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter{
		CellID:         cellID,
		OrganizationID: response.OrganizationID,
		ResponseID:     responseID,
	})
	if err != nil {
		return nil, err
	}
	directiveExtensionAppealReconciliationChallengeAppeals, err = s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter{
		CellID:         cellID,
		OrganizationID: response.OrganizationID,
		ResponseID:     responseID,
	})
	if err != nil {
		return nil, err
	}

	reportSummaries, err := s.ListFederationIncidentReports(ctx, SecureCellFederationIncidentReportFilter{
		CellID:         cellID,
		OrganizationID: response.OrganizationID,
		ResponseID:     responseID,
	})
	if err != nil {
		return nil, err
	}
	reportBundles := make([]*SecureCellFederationIncidentReportBundle, 0, len(reportSummaries))
	amendmentBundles := make([]*SecureCellFederationIncidentReportAmendmentBundle, 0)
	for _, report := range reportSummaries {
		reportBundle, err := s.BuildFederationIncidentReportBundle(ctx, cellID, report.ReportID, SecureCellFederationIncidentReportBundleOptions{})
		if err != nil {
			return nil, err
		}
		reportBundles = append(reportBundles, reportBundle)

		amendments, err := s.ListFederationIncidentReportAmendments(ctx, SecureCellFederationIncidentReportAmendmentFilter{
			CellID:   cellID,
			ReportID: report.ReportID,
		})
		if err != nil {
			return nil, err
		}
		for _, amendment := range amendments {
			amendmentBundle, err := s.BuildFederationIncidentReportAmendmentBundle(ctx, cellID, amendment.AmendmentID, SecureCellFederationIncidentReportAmendmentBundleOptions{})
			if err != nil {
				return nil, err
			}
			amendmentBundles = append(amendmentBundles, amendmentBundle)
		}
	}

	reportReconciliations, err := s.ListFederationIncidentReportReconciliations(ctx, SecureCellFederationIncidentReportReconciliationFilter{
		CellID:         cellID,
		OrganizationID: response.OrganizationID,
		IncidentID:     response.IncidentID,
	})
	if err != nil {
		return nil, err
	}
	reportReconciliationBundles := make([]*SecureCellFederationIncidentReportReconciliationBundle, 0, len(reportReconciliations))
	for _, reconciliation := range reportReconciliations {
		reconciliationBundle, err := s.BuildFederationIncidentReportReconciliationBundle(ctx, cellID, reconciliation.ComparisonKey, SecureCellFederationIncidentReportReconciliationBundleOptions{})
		if err != nil {
			return nil, err
		}
		reportReconciliationBundles = append(reportReconciliationBundles, reconciliationBundle)
	}

	amendmentReconciliations, err := s.ListFederationIncidentReportAmendmentReconciliations(ctx, SecureCellFederationIncidentReportAmendmentReconciliationFilter{
		CellID:         cellID,
		OrganizationID: response.OrganizationID,
		IncidentID:     response.IncidentID,
	})
	if err != nil {
		return nil, err
	}
	amendmentReconciliationBundles := make([]*SecureCellFederationIncidentReportAmendmentReconciliationBundle, 0, len(amendmentReconciliations))
	for _, reconciliation := range amendmentReconciliations {
		reconciliationBundle, err := s.BuildFederationIncidentReportAmendmentReconciliationBundle(ctx, cellID, reconciliation.ComparisonKey, SecureCellFederationIncidentReportAmendmentReconciliationBundleOptions{})
		if err != nil {
			return nil, err
		}
		amendmentReconciliationBundles = append(amendmentReconciliationBundles, reconciliationBundle)
	}

	responseActions, err := s.ListFederationIncidentResponseActions(ctx, SecureCellFederationIncidentResponseActionFilter{
		CellID:     cellID,
		ResponseID: responseID,
	})
	if err != nil {
		return nil, err
	}
	directiveAutomationActions, err := s.ListFederationIncidentDirectiveAutomationActions(ctx, SecureCellFederationIncidentDirectiveAutomationActionFilter{
		CellID:     cellID,
		ResponseID: responseID,
	})
	if err != nil {
		return nil, err
	}
	directiveExtensionDisputes, err := s.ListFederationIncidentDirectiveExtensionDisputes(ctx, SecureCellFederationIncidentDirectiveExtensionDisputeFilter{
		CellID:     cellID,
		ResponseID: responseID,
	})
	if err != nil {
		return nil, err
	}
	directiveExtensionAutomationActions, err := s.ListFederationIncidentDirectiveExtensionAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAutomationActionFilter{
		CellID:     cellID,
		ResponseID: responseID,
	})
	if err != nil {
		return nil, err
	}
	directiveExtensionAppealAutomationActions, err := s.ListFederationIncidentDirectiveExtensionAppealAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionFilter{
		CellID:     cellID,
		ResponseID: responseID,
	})
	if err != nil {
		return nil, err
	}
	directiveExtensionAppealReconciliationAutomationActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionFilter{
		CellID:     cellID,
		ResponseID: responseID,
	})
	if err != nil {
		return nil, err
	}
	directiveExtensionAppealReconciliationChallengeAutomationActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionFilter{
		CellID:     cellID,
		ResponseID: responseID,
	})
	if err != nil {
		return nil, err
	}
	directiveExtensionAppealReconciliationChallengeActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFilter{
		CellID:     cellID,
		ResponseID: responseID,
	})
	if err != nil {
		return nil, err
	}
	directiveExtensionAppealReconciliationChallengeAppealActions, err := s.ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActions(ctx, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter{
		CellID:     cellID,
		ResponseID: responseID,
	})
	if err != nil {
		return nil, err
	}
	remediations, err := s.ListFederationIncidentRemediations(ctx, SecureCellFederationIncidentRemediationFilter{
		CellID:     cellID,
		ResponseID: responseID,
	})
	if err != nil {
		return nil, err
	}
	verifications, err := s.ListFederationIncidentVerifications(ctx, SecureCellFederationIncidentVerificationFilter{
		CellID:     cellID,
		ResponseID: responseID,
	})
	if err != nil {
		return nil, err
	}
	closures, err := s.ListFederationIncidentClosureAttestations(ctx, SecureCellFederationIncidentClosureAttestationFilter{
		CellID:     cellID,
		ResponseID: responseID,
	})
	if err != nil {
		return nil, err
	}
	disputes, err := s.ListFederationIncidentDisputes(ctx, SecureCellFederationIncidentDisputeFilter{
		CellID:     cellID,
		ResponseID: responseID,
	})
	if err != nil {
		return nil, err
	}
	reportReconciliationAutomationActions, err := s.ListFederationIncidentReportReconciliationAutomationActions(ctx, SecureCellFederationIncidentReportReconciliationAutomationActionFilter{
		CellID:     cellID,
		IncidentID: response.IncidentID,
	})
	if err != nil {
		return nil, err
	}
	amendmentReconciliationAttestations, err := s.ListFederationIncidentReportAmendmentReconciliationCounterpartyAttestations(ctx, SecureCellFederationIncidentReportAmendmentReconciliationCounterpartyAttestationFilter{
		CellID:         cellID,
		OrganizationID: response.OrganizationID,
		IncidentID:     response.IncidentID,
	})
	if err != nil {
		return nil, err
	}
	amendmentReconciliationAutomationActions, err := s.ListFederationIncidentReportAmendmentReconciliationAutomationActions(ctx, SecureCellFederationIncidentReportAmendmentReconciliationAutomationActionFilter{
		CellID:     cellID,
		IncidentID: response.IncidentID,
	})
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(72 * time.Hour)
	if options.ExpiresAfter != 0 {
		expiresAt = now.Add(options.ExpiresAfter)
	}
	pack := &SecureCellFederationIncidentCasePack{
		ID:                              firstNonEmpty(strings.TrimSpace(options.ID), fmt.Sprintf("%s-%s-case-pack", run.result.CellID, response.ID)),
		Version:                         firstNonEmpty(strings.TrimSpace(options.Version), "v1"),
		Name:                            firstNonEmpty(strings.TrimSpace(options.Name), fmt.Sprintf("Federation Incident Case Pack %s", response.ID)),
		GeneratedAt:                     now,
		ExpiresAt:                       cloneTimePtr(&expiresAt),
		CellID:                          run.result.CellID,
		CellName:                        run.result.Name,
		CellStatus:                      run.result.Status,
		Jurisdiction:                    run.request.Jurisdiction,
		Framework:                       firstNonEmpty(strings.TrimSpace(s.config.Framework), "Secure Cells v1"),
		Organization:                    orgSummary,
		ResponseSummary:                 responseSummary,
		ResponseBundle:                  responseBundle,
		DirectiveBundles:                directiveBundles,
		DirectiveExtensionSummaries:     directiveExtensionSummaries,
		DirectiveExtensionAppealBundles: directiveExtensionAppealBundles,
		DirectiveExtensionAppealReconciliationBundles:          directiveExtensionAppealReconciliationBundles,
		DirectiveExtensionAppealReconciliationChallenges:       directiveExtensionAppealReconciliationChallenges,
		DirectiveExtensionAppealReconciliationChallengeAppeals: directiveExtensionAppealReconciliationChallengeAppeals,
		ReportBundles:                                           reportBundles,
		AmendmentBundles:                                        amendmentBundles,
		ReportReconciliationBundles:                             reportReconciliationBundles,
		AmendmentReconciliationBundles:                          amendmentReconciliationBundles,
		ResponseActions:                                         responseActions,
		DirectiveAutomationActions:                              directiveAutomationActions,
		DirectiveExtensionDisputes:                              directiveExtensionDisputes,
		DirectiveExtensionAppealAutomationActions:               directiveExtensionAppealAutomationActions,
		DirectiveExtensionAppealReconciliationAutomationActions: directiveExtensionAppealReconciliationAutomationActions,
		DirectiveExtensionAppealReconciliationChallengeAutomationActions: directiveExtensionAppealReconciliationChallengeAutomationActions,
		DirectiveExtensionAppealReconciliationChallengeActions:           directiveExtensionAppealReconciliationChallengeActions,
		DirectiveExtensionAppealReconciliationChallengeAppealActions:     directiveExtensionAppealReconciliationChallengeAppealActions,
		DirectiveExtensionAutomationActions:                              directiveExtensionAutomationActions,
		Remediations:                                                     remediations,
		Verifications:                                                    verifications,
		Closures:                                                         closures,
		Disputes:                                                         disputes,
		ReportReconciliationAutomationActions:                            reportReconciliationAutomationActions,
		AmendmentReconciliationAttestations:                              amendmentReconciliationAttestations,
		AmendmentReconciliationAutomationActions:                         amendmentReconciliationAutomationActions,
		Controls:                                                         secureCellFederationControlsFromLedger(run.result.ControlLedger),
		OperatorSurfaces:                                                 cloneSecureCellFederationOperatorSurfaces(options.OperatorSurfaces),
		Metadata:                                                         cloneStringMap(options.Metadata),
	}
	if run.result.ControlLedger != nil && run.result.ControlLedger.Bundle != nil {
		pack.ControlLedgerID = strings.TrimSpace(run.result.ControlLedger.Bundle.ID)
		pack.ControlLedgerHash = strings.TrimSpace(run.result.ControlLedger.Bundle.ContentHash)
	}
	if run.result.PortablePackage != nil {
		pack.PortablePackageHash = strings.TrimSpace(run.result.PortablePackage.PackageHash)
		pack.PortablePackageSigned = run.result.PortablePackage.Signature != nil
		pack.PortablePackageAnchored = run.result.PortablePackage.AuditAnchor != nil
	}
	if s.config.FederationIncidentCasePackSigner != nil {
		if err := s.config.FederationIncidentCasePackSigner(ctx, pack); err != nil {
			return nil, fmt.Errorf("securecells/federation-incident-case-pack: external case-pack signing failed: %w", err)
		}
	} else if err := SignFederationIncidentCasePackEd25519(pack, s.config.PackageSigningKey, strings.TrimSpace(s.config.PackageSigner), s.config.IncludeVerificationKeys); err != nil {
		return nil, err
	}
	return pack, nil
}

// VerifyFederationIncidentCasePack validates one signed case pack.
func VerifyFederationIncidentCasePack(pack *SecureCellFederationIncidentCasePack) error {
	if pack == nil {
		return fmt.Errorf("securecells/federation-incident-case-pack: case pack is required")
	}
	digest := secureCellFederationIncidentCasePackDigest(pack)
	expectedHash := hex.EncodeToString(digest[:])
	if strings.TrimSpace(pack.ContentHash) == "" {
		return fmt.Errorf("securecells/federation-incident-case-pack: content hash is required")
	}
	if !strings.EqualFold(strings.TrimSpace(pack.ContentHash), expectedHash) {
		return fmt.Errorf("securecells/federation-incident-case-pack: content hash mismatch")
	}
	if pack.Signature == nil {
		return fmt.Errorf("securecells/federation-incident-case-pack: signature is required")
	}
	if algorithm := strings.ToLower(strings.TrimSpace(pack.Signature.Algorithm)); algorithm != secureCellFederationIncidentCasePackSignatureAlgorithmED25519 {
		return fmt.Errorf("securecells/federation-incident-case-pack: unsupported signature algorithm %q", pack.Signature.Algorithm)
	}
	publicKeyBytes, err := hex.DecodeString(strings.TrimSpace(pack.Signature.PublicKey))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-case-pack: decode public key: %w", err)
	}
	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("securecells/federation-incident-case-pack: invalid public key size")
	}
	signatureBytes, err := hex.DecodeString(strings.TrimSpace(pack.Signature.Signature))
	if err != nil {
		return fmt.Errorf("securecells/federation-incident-case-pack: decode signature: %w", err)
	}
	if len(signatureBytes) != ed25519.SignatureSize {
		return fmt.Errorf("securecells/federation-incident-case-pack: invalid signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), digest[:], signatureBytes) {
		return fmt.Errorf("securecells/federation-incident-case-pack: signature verification failed")
	}
	return nil
}

// SignFederationIncidentCasePackEd25519 signs one case pack.
func SignFederationIncidentCasePackEd25519(pack *SecureCellFederationIncidentCasePack, privateKey ed25519.PrivateKey, signer string, includeVerificationKeys bool) error {
	if pack == nil {
		return fmt.Errorf("securecells/federation-incident-case-pack: case pack is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("securecells/federation-incident-case-pack: ed25519 private key is required")
	}
	now := time.Now().UTC()
	digest := secureCellFederationIncidentCasePackDigest(pack)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, digest[:])

	pack.ContentHash = hex.EncodeToString(digest[:])
	pack.Signature = &SecureCellFederationIncidentCasePackSignature{
		Algorithm: secureCellFederationIncidentCasePackSignatureAlgorithmED25519,
		Signer:    strings.TrimSpace(signer),
		KeyID:     fmt.Sprintf("ed25519:%x", sha256.Sum256(publicKey)),
		Signature: hex.EncodeToString(signature),
		SignedAt:  now,
	}
	if includeVerificationKeys {
		pack.Signature.PublicKey = hex.EncodeToString(publicKey)
	}
	return nil
}

func secureCellFederationIncidentCasePackDigest(pack *SecureCellFederationIncidentCasePack) [32]byte {
	clone := *pack
	clone.Signature = nil
	clone.ContentHash = ""
	payload, _ := json.Marshal(clone)
	return sha256.Sum256(payload)
}
