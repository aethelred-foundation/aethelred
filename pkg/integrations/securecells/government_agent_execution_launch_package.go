package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchPackageStatus describes whether the
// portable launch package is blocked, waiting for review, or launch-ready.
type SecureCellGovernmentAgentExecutionLaunchPackageStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchPackageBlocked        SecureCellGovernmentAgentExecutionLaunchPackageStatus = "blocked"
	SecureCellGovernmentAgentExecutionLaunchPackageReviewRequired SecureCellGovernmentAgentExecutionLaunchPackageStatus = "operator_review_required"
	SecureCellGovernmentAgentExecutionLaunchPackageReady          SecureCellGovernmentAgentExecutionLaunchPackageStatus = "ready_for_launch"
)

// SecureCellGovernmentAgentExecutionLaunchPackage is the portable launch
// artifact operators can hand to an executor after validation.
type SecureCellGovernmentAgentExecutionLaunchPackage struct {
	PackageID                            string                                                          `json:"package_id"`
	PackageVersion                       string                                                          `json:"package_version"`
	CellID                               string                                                          `json:"cell_id"`
	Name                                 string                                                          `json:"name"`
	Jurisdiction                         string                                                          `json:"jurisdiction,omitempty"`
	ServiceCode                          string                                                          `json:"service_code,omitempty"`
	ServiceTier                          string                                                          `json:"service_tier,omitempty"`
	Status                               SecureCellGovernmentAgentExecutionLaunchPackageStatus           `json:"status"`
	AuthorizationStatus                  SecureCellGovernmentAgentExecutionLaunchAuthorizationStatus     `json:"authorization_status"`
	ClearanceStatus                      SecureCellGovernmentAgentExecutionLaunchClearanceStatus         `json:"clearance_status"`
	ReceiptManifestStatus                SecureCellGovernmentAgentExecutionLaunchReceiptManifestStatus   `json:"receipt_manifest_status"`
	ReceiptValidationStatus              SecureCellGovernmentAgentExecutionLaunchReceiptValidationStatus `json:"receipt_validation_status"`
	CanLaunchNow                         bool                                                            `json:"can_launch_now"`
	CanLaunchAfterOperatorReview         bool                                                            `json:"can_launch_after_operator_review"`
	CanAutonomousLaunch                  bool                                                            `json:"can_autonomous_launch"`
	RequiredOperatorAcknowledgementCount int                                                             `json:"required_operator_acknowledgement_count"`
	ClearanceItemCount                   int                                                             `json:"clearance_item_count"`
	ReceiptRequirementCount              int                                                             `json:"receipt_requirement_count"`
	PendingAcknowledgementReceiptCount   int                                                             `json:"pending_acknowledgement_receipt_count"`
	BlockedReceiptCount                  int                                                             `json:"blocked_receipt_count"`
	ValidationFailCount                  int                                                             `json:"validation_fail_count"`
	RequiredReceiptTypes                 []string                                                        `json:"required_receipt_types,omitempty"`
	OperatorInstructions                 []string                                                        `json:"operator_instructions,omitempty"`
	AuthorizationID                      string                                                          `json:"authorization_id"`
	ClearanceRegisterID                  string                                                          `json:"clearance_register_id"`
	ReceiptManifestID                    string                                                          `json:"receipt_manifest_id"`
	ReceiptValidationID                  string                                                          `json:"receipt_validation_id"`
	LaunchDigest                         string                                                          `json:"launch_digest"`
	ClearanceDigest                      string                                                          `json:"clearance_digest"`
	ReceiptManifestDigest                string                                                          `json:"receipt_manifest_digest"`
	ReceiptValidationDigest              string                                                          `json:"receipt_validation_digest"`
	Authorization                        SecureCellGovernmentAgentExecutionLaunchAuthorization           `json:"authorization"`
	Clearance                            SecureCellGovernmentAgentExecutionLaunchClearanceRegister       `json:"clearance"`
	ReceiptManifest                      SecureCellGovernmentAgentExecutionLaunchReceiptManifest         `json:"receipt_manifest"`
	ReceiptValidation                    SecureCellGovernmentAgentExecutionLaunchReceiptValidation       `json:"receipt_validation"`
	PackageDigest                        string                                                          `json:"package_digest"`
	GeneratedAt                          time.Time                                                       `json:"generated_at"`
	UpdatedAt                            time.Time                                                       `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchPackage returns the portable launch package
// for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchPackage(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchPackage, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchPackages(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-package: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchPackages returns portable launch packages
// for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchPackages(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchPackage, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-package: service is required")
	}
	authorizations, err := s.ListGovernmentAgentExecutionLaunchAuthorizations(ctx, filter)
	if err != nil {
		return nil, err
	}
	clearances, err := s.ListGovernmentAgentExecutionLaunchClearances(ctx, filter)
	if err != nil {
		return nil, err
	}
	manifests, err := s.ListGovernmentAgentExecutionLaunchReceiptManifests(ctx, filter)
	if err != nil {
		return nil, err
	}
	validations, err := s.ListGovernmentAgentExecutionLaunchReceiptValidations(ctx, filter)
	if err != nil {
		return nil, err
	}
	clearanceByCellID := make(map[string]SecureCellGovernmentAgentExecutionLaunchClearanceRegister, len(clearances))
	for _, clearance := range clearances {
		clearanceByCellID[clearance.CellID] = clearance
	}
	manifestByCellID := make(map[string]SecureCellGovernmentAgentExecutionLaunchReceiptManifest, len(manifests))
	for _, manifest := range manifests {
		manifestByCellID[manifest.CellID] = manifest
	}
	validationByCellID := make(map[string]SecureCellGovernmentAgentExecutionLaunchReceiptValidation, len(validations))
	for _, validation := range validations {
		validationByCellID[validation.CellID] = validation
	}
	now := time.Now().UTC()
	packages := make([]SecureCellGovernmentAgentExecutionLaunchPackage, 0, len(authorizations))
	for _, authorization := range authorizations {
		clearance, clearanceOK := clearanceByCellID[authorization.CellID]
		manifest, manifestOK := manifestByCellID[authorization.CellID]
		validation, validationOK := validationByCellID[authorization.CellID]
		if !clearanceOK || !manifestOK || !validationOK {
			continue
		}
		packages = append(packages, secureCellGovernmentAgentExecutionLaunchPackage(authorization, clearance, manifest, validation, now))
	}
	sort.SliceStable(packages, func(i, j int) bool {
		if packages[i].Status == packages[j].Status {
			if packages[i].ValidationFailCount == packages[j].ValidationFailCount {
				if packages[i].BlockedReceiptCount == packages[j].BlockedReceiptCount {
					return packages[i].CellID < packages[j].CellID
				}
				return packages[i].BlockedReceiptCount > packages[j].BlockedReceiptCount
			}
			return packages[i].ValidationFailCount > packages[j].ValidationFailCount
		}
		return secureCellGovernmentAgentExecutionLaunchPackageStatusRank(packages[i].Status) < secureCellGovernmentAgentExecutionLaunchPackageStatusRank(packages[j].Status)
	})
	return packages, nil
}

func secureCellGovernmentAgentExecutionLaunchPackage(
	authorization SecureCellGovernmentAgentExecutionLaunchAuthorization,
	clearance SecureCellGovernmentAgentExecutionLaunchClearanceRegister,
	manifest SecureCellGovernmentAgentExecutionLaunchReceiptManifest,
	validation SecureCellGovernmentAgentExecutionLaunchReceiptValidation,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchPackage {
	pkg := SecureCellGovernmentAgentExecutionLaunchPackage{
		PackageVersion:                       "secure-cell-government-agent-execution-launch/v1",
		CellID:                               authorization.CellID,
		Name:                                 authorization.Name,
		Jurisdiction:                         authorization.Jurisdiction,
		ServiceCode:                          authorization.ServiceCode,
		ServiceTier:                          authorization.ServiceTier,
		AuthorizationStatus:                  authorization.Status,
		ClearanceStatus:                      clearance.Status,
		ReceiptManifestStatus:                manifest.Status,
		ReceiptValidationStatus:              validation.Status,
		CanLaunchNow:                         authorization.CanLaunchNow,
		CanLaunchAfterOperatorReview:         authorization.CanLaunchAfterOperatorReview,
		CanAutonomousLaunch:                  authorization.CanAutonomousLaunch,
		RequiredOperatorAcknowledgementCount: authorization.RequiredOperatorAcknowledgementCount,
		ClearanceItemCount:                   clearance.ClearanceItemCount,
		ReceiptRequirementCount:              manifest.ReceiptRequirementCount,
		PendingAcknowledgementReceiptCount:   manifest.PendingAcknowledgementReceiptCount,
		BlockedReceiptCount:                  manifest.BlockedReceiptCount,
		ValidationFailCount:                  validation.FailCount,
		RequiredReceiptTypes:                 append([]string(nil), manifest.RequiredReceiptTypes...),
		AuthorizationID:                      authorization.AuthorizationID,
		ClearanceRegisterID:                  clearance.RegisterID,
		ReceiptManifestID:                    manifest.ManifestID,
		ReceiptValidationID:                  validation.ValidationID,
		LaunchDigest:                         authorization.LaunchDigest,
		ClearanceDigest:                      clearance.RegisterDigest,
		ReceiptManifestDigest:                manifest.ManifestDigest,
		ReceiptValidationDigest:              validation.ValidationDigest,
		Authorization:                        authorization,
		Clearance:                            clearance,
		ReceiptManifest:                      manifest,
		ReceiptValidation:                    validation,
		GeneratedAt:                          generatedAt.UTC(),
		UpdatedAt:                            validation.UpdatedAt.UTC(),
	}
	pkg.Status = secureCellGovernmentAgentExecutionLaunchPackageStatus(pkg)
	pkg.CanLaunchNow = pkg.Status == SecureCellGovernmentAgentExecutionLaunchPackageReady && authorization.CanLaunchNow
	pkg.CanLaunchAfterOperatorReview = pkg.Status == SecureCellGovernmentAgentExecutionLaunchPackageReviewRequired && authorization.CanLaunchAfterOperatorReview
	pkg.CanAutonomousLaunch = pkg.Status == SecureCellGovernmentAgentExecutionLaunchPackageReady && authorization.CanAutonomousLaunch
	pkg.OperatorInstructions = secureCellGovernmentAgentExecutionLaunchPackageInstructions(pkg)
	pkg.PackageDigest = secureCellGovernmentAgentExecutionLaunchPackageDigest(pkg)
	pkg.PackageID = "government-agent-execution-launch-package:" + pkg.CellID + ":" + pkg.PackageDigest[:12]
	return pkg
}

func secureCellGovernmentAgentExecutionLaunchPackageStatus(pkg SecureCellGovernmentAgentExecutionLaunchPackage) SecureCellGovernmentAgentExecutionLaunchPackageStatus {
	if pkg.ValidationFailCount > 0 ||
		pkg.AuthorizationStatus == SecureCellGovernmentAgentExecutionLaunchAuthorizationBlocked ||
		pkg.ClearanceStatus == SecureCellGovernmentAgentExecutionLaunchClearanceBlocked ||
		pkg.ReceiptManifestStatus == SecureCellGovernmentAgentExecutionLaunchReceiptManifestBlocked ||
		pkg.ReceiptValidationStatus == SecureCellGovernmentAgentExecutionLaunchReceiptValidationBlocked ||
		pkg.ReceiptValidationStatus == SecureCellGovernmentAgentExecutionLaunchReceiptValidationFailed {
		return SecureCellGovernmentAgentExecutionLaunchPackageBlocked
	}
	if pkg.PendingAcknowledgementReceiptCount > 0 ||
		pkg.AuthorizationStatus == SecureCellGovernmentAgentExecutionLaunchAuthorizationOperatorReviewRequired ||
		pkg.ClearanceStatus == SecureCellGovernmentAgentExecutionLaunchClearanceHeldForReview ||
		pkg.ReceiptManifestStatus == SecureCellGovernmentAgentExecutionLaunchReceiptManifestAwaitingAcknowledgements {
		return SecureCellGovernmentAgentExecutionLaunchPackageReviewRequired
	}
	return SecureCellGovernmentAgentExecutionLaunchPackageReady
}

func secureCellGovernmentAgentExecutionLaunchPackageInstructions(pkg SecureCellGovernmentAgentExecutionLaunchPackage) []string {
	instructions := make([]string, 0, 4)
	switch pkg.Status {
	case SecureCellGovernmentAgentExecutionLaunchPackageBlocked:
		instructions = append(instructions, "Resolve blocked launch receipts or failed validation checks before execution.")
	case SecureCellGovernmentAgentExecutionLaunchPackageReviewRequired:
		instructions = append(instructions, "Collect operator acknowledgement receipts before execution.")
	default:
		instructions = append(instructions, "Launch only with the package digest and receipt manifest preserved.")
	}
	if pkg.ValidationFailCount > 0 {
		instructions = append(instructions, "Regenerate receipt validation after correcting failed checks.")
	}
	if pkg.BlockedReceiptCount > 0 {
		instructions = append(instructions, "Complete remediation receipts and regenerate the launch package.")
	}
	if pkg.ReceiptRequirementCount > 0 {
		instructions = append(instructions, "Attach every listed receipt to the evidence binding in the manifest.")
	}
	return uniqueSortedStrings(instructions)
}

func secureCellGovernmentAgentExecutionLaunchPackageStatusRank(status SecureCellGovernmentAgentExecutionLaunchPackageStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchPackageBlocked:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchPackageReviewRequired:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchPackageReady:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchPackageDigest(pkg SecureCellGovernmentAgentExecutionLaunchPackage) string {
	core := struct {
		PackageVersion                       string                                                `json:"package_version"`
		CellID                               string                                                `json:"cell_id"`
		Status                               SecureCellGovernmentAgentExecutionLaunchPackageStatus `json:"status"`
		CanLaunchNow                         bool                                                  `json:"can_launch_now"`
		CanLaunchAfterOperatorReview         bool                                                  `json:"can_launch_after_operator_review"`
		CanAutonomousLaunch                  bool                                                  `json:"can_autonomous_launch"`
		RequiredOperatorAcknowledgementCount int                                                   `json:"required_operator_acknowledgement_count"`
		ReceiptRequirementCount              int                                                   `json:"receipt_requirement_count"`
		PendingAcknowledgementReceiptCount   int                                                   `json:"pending_acknowledgement_receipt_count"`
		BlockedReceiptCount                  int                                                   `json:"blocked_receipt_count"`
		ValidationFailCount                  int                                                   `json:"validation_fail_count"`
		RequiredReceiptTypes                 []string                                              `json:"required_receipt_types,omitempty"`
		OperatorInstructions                 []string                                              `json:"operator_instructions,omitempty"`
		AuthorizationID                      string                                                `json:"authorization_id"`
		ClearanceRegisterID                  string                                                `json:"clearance_register_id"`
		ReceiptManifestID                    string                                                `json:"receipt_manifest_id"`
		ReceiptValidationID                  string                                                `json:"receipt_validation_id"`
		LaunchDigest                         string                                                `json:"launch_digest"`
		ClearanceDigest                      string                                                `json:"clearance_digest"`
		ReceiptManifestDigest                string                                                `json:"receipt_manifest_digest"`
		ReceiptValidationDigest              string                                                `json:"receipt_validation_digest"`
	}{
		PackageVersion:                       pkg.PackageVersion,
		CellID:                               pkg.CellID,
		Status:                               pkg.Status,
		CanLaunchNow:                         pkg.CanLaunchNow,
		CanLaunchAfterOperatorReview:         pkg.CanLaunchAfterOperatorReview,
		CanAutonomousLaunch:                  pkg.CanAutonomousLaunch,
		RequiredOperatorAcknowledgementCount: pkg.RequiredOperatorAcknowledgementCount,
		ReceiptRequirementCount:              pkg.ReceiptRequirementCount,
		PendingAcknowledgementReceiptCount:   pkg.PendingAcknowledgementReceiptCount,
		BlockedReceiptCount:                  pkg.BlockedReceiptCount,
		ValidationFailCount:                  pkg.ValidationFailCount,
		RequiredReceiptTypes:                 pkg.RequiredReceiptTypes,
		OperatorInstructions:                 pkg.OperatorInstructions,
		AuthorizationID:                      pkg.AuthorizationID,
		ClearanceRegisterID:                  pkg.ClearanceRegisterID,
		ReceiptManifestID:                    pkg.ReceiptManifestID,
		ReceiptValidationID:                  pkg.ReceiptValidationID,
		LaunchDigest:                         pkg.LaunchDigest,
		ClearanceDigest:                      pkg.ClearanceDigest,
		ReceiptManifestDigest:                pkg.ReceiptManifestDigest,
		ReceiptValidationDigest:              pkg.ReceiptValidationDigest,
	}
	return EvidenceHash(core)
}
