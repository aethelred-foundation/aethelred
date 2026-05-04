package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchReceiptValidationStatus describes
// whether a launch receipt manifest is internally valid.
type SecureCellGovernmentAgentExecutionLaunchReceiptValidationStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchReceiptValidationFailed  SecureCellGovernmentAgentExecutionLaunchReceiptValidationStatus = "validation_failed"
	SecureCellGovernmentAgentExecutionLaunchReceiptValidationBlocked SecureCellGovernmentAgentExecutionLaunchReceiptValidationStatus = "validation_blocked"
	SecureCellGovernmentAgentExecutionLaunchReceiptValidationReady   SecureCellGovernmentAgentExecutionLaunchReceiptValidationStatus = "validation_ready"
)

// SecureCellGovernmentAgentExecutionLaunchReceiptValidationOutcome records one
// receipt validation check outcome.
type SecureCellGovernmentAgentExecutionLaunchReceiptValidationOutcome string

const (
	SecureCellGovernmentAgentExecutionLaunchReceiptValidationPass SecureCellGovernmentAgentExecutionLaunchReceiptValidationOutcome = "pass"
	SecureCellGovernmentAgentExecutionLaunchReceiptValidationWarn SecureCellGovernmentAgentExecutionLaunchReceiptValidationOutcome = "warn"
	SecureCellGovernmentAgentExecutionLaunchReceiptValidationFail SecureCellGovernmentAgentExecutionLaunchReceiptValidationOutcome = "fail"
)

// SecureCellGovernmentAgentExecutionLaunchReceiptValidationCheck is one
// deterministic check over a launch receipt requirement.
type SecureCellGovernmentAgentExecutionLaunchReceiptValidationCheck struct {
	CheckID       string                                                           `json:"check_id"`
	RequirementID string                                                           `json:"requirement_id,omitempty"`
	ReceiptType   string                                                           `json:"receipt_type,omitempty"`
	Code          string                                                           `json:"code"`
	Outcome       SecureCellGovernmentAgentExecutionLaunchReceiptValidationOutcome `json:"outcome"`
	Detail        string                                                           `json:"detail"`
	Remediation   string                                                           `json:"remediation,omitempty"`
	GeneratedAt   time.Time                                                        `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchReceiptValidation is the validation
// matrix for one launch receipt manifest.
type SecureCellGovernmentAgentExecutionLaunchReceiptValidation struct {
	ValidationID                       string                                                           `json:"validation_id"`
	ManifestID                         string                                                           `json:"manifest_id"`
	RegisterID                         string                                                           `json:"register_id"`
	AuthorizationID                    string                                                           `json:"authorization_id"`
	VerificationID                     string                                                           `json:"verification_id"`
	BundleID                           string                                                           `json:"bundle_id"`
	CellID                             string                                                           `json:"cell_id"`
	Name                               string                                                           `json:"name"`
	Jurisdiction                       string                                                           `json:"jurisdiction,omitempty"`
	ServiceCode                        string                                                           `json:"service_code,omitempty"`
	ServiceTier                        string                                                           `json:"service_tier,omitempty"`
	Status                             SecureCellGovernmentAgentExecutionLaunchReceiptValidationStatus  `json:"status"`
	ManifestStatus                     SecureCellGovernmentAgentExecutionLaunchReceiptManifestStatus    `json:"manifest_status"`
	ClearanceStatus                    SecureCellGovernmentAgentExecutionLaunchClearanceStatus          `json:"clearance_status"`
	CanAcceptReceipts                  bool                                                             `json:"can_accept_receipts"`
	CanLaunchAfterReceipts             bool                                                             `json:"can_launch_after_receipts"`
	CheckCount                         int                                                              `json:"check_count"`
	PassCount                          int                                                              `json:"pass_count"`
	WarnCount                          int                                                              `json:"warn_count"`
	FailCount                          int                                                              `json:"fail_count"`
	ReceiptRequirementCount            int                                                              `json:"receipt_requirement_count"`
	PendingAcknowledgementReceiptCount int                                                              `json:"pending_acknowledgement_receipt_count"`
	PendingCollectionReceiptCount      int                                                              `json:"pending_collection_receipt_count"`
	BlockedReceiptCount                int                                                              `json:"blocked_receipt_count"`
	RequiredReceiptTypes               []string                                                         `json:"required_receipt_types,omitempty"`
	Checks                             []SecureCellGovernmentAgentExecutionLaunchReceiptValidationCheck `json:"checks"`
	ManifestDigest                     string                                                           `json:"manifest_digest"`
	RegisterDigest                     string                                                           `json:"register_digest"`
	LaunchDigest                       string                                                           `json:"launch_digest"`
	ValidationDigest                   string                                                           `json:"validation_digest"`
	GeneratedAt                        time.Time                                                        `json:"generated_at"`
	UpdatedAt                          time.Time                                                        `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchReceiptValidation returns the validation
// matrix for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchReceiptValidation(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchReceiptValidation, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchReceiptValidations(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-receipt-validation: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchReceiptValidations returns validation
// matrices for matching government-service launch receipt manifests.
func (s *Service) ListGovernmentAgentExecutionLaunchReceiptValidations(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchReceiptValidation, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-receipt-validation: service is required")
	}
	manifests, err := s.ListGovernmentAgentExecutionLaunchReceiptManifests(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	validations := make([]SecureCellGovernmentAgentExecutionLaunchReceiptValidation, 0, len(manifests))
	for _, manifest := range manifests {
		validations = append(validations, secureCellGovernmentAgentExecutionLaunchReceiptValidation(manifest, now))
	}
	sort.SliceStable(validations, func(i, j int) bool {
		if validations[i].Status == validations[j].Status {
			if validations[i].FailCount == validations[j].FailCount {
				if validations[i].WarnCount == validations[j].WarnCount {
					return validations[i].CellID < validations[j].CellID
				}
				return validations[i].WarnCount > validations[j].WarnCount
			}
			return validations[i].FailCount > validations[j].FailCount
		}
		return secureCellGovernmentAgentExecutionLaunchReceiptValidationStatusRank(validations[i].Status) < secureCellGovernmentAgentExecutionLaunchReceiptValidationStatusRank(validations[j].Status)
	})
	return validations, nil
}

func secureCellGovernmentAgentExecutionLaunchReceiptValidation(
	manifest SecureCellGovernmentAgentExecutionLaunchReceiptManifest,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchReceiptValidation {
	checks := make([]SecureCellGovernmentAgentExecutionLaunchReceiptValidationCheck, 0, len(manifest.Requirements)*5+2)
	checks = append(checks, secureCellGovernmentAgentExecutionLaunchReceiptManifestCheck(manifest, generatedAt))
	for _, requirement := range manifest.Requirements {
		checks = append(checks, secureCellGovernmentAgentExecutionLaunchReceiptRequirementChecks(requirement, generatedAt)...)
	}
	validation := SecureCellGovernmentAgentExecutionLaunchReceiptValidation{
		ManifestID:                         manifest.ManifestID,
		RegisterID:                         manifest.RegisterID,
		AuthorizationID:                    manifest.AuthorizationID,
		VerificationID:                     manifest.VerificationID,
		BundleID:                           manifest.BundleID,
		CellID:                             manifest.CellID,
		Name:                               manifest.Name,
		Jurisdiction:                       manifest.Jurisdiction,
		ServiceCode:                        manifest.ServiceCode,
		ServiceTier:                        manifest.ServiceTier,
		ManifestStatus:                     manifest.Status,
		ClearanceStatus:                    manifest.ClearanceStatus,
		CanAcceptReceipts:                  manifest.CanAcceptReceipts,
		CanLaunchAfterReceipts:             manifest.CanLaunchAfterReceipts,
		ReceiptRequirementCount:            manifest.ReceiptRequirementCount,
		PendingAcknowledgementReceiptCount: manifest.PendingAcknowledgementReceiptCount,
		PendingCollectionReceiptCount:      manifest.PendingCollectionReceiptCount,
		BlockedReceiptCount:                manifest.BlockedReceiptCount,
		RequiredReceiptTypes:               append([]string(nil), manifest.RequiredReceiptTypes...),
		Checks:                             checks,
		ManifestDigest:                     manifest.ManifestDigest,
		RegisterDigest:                     manifest.RegisterDigest,
		LaunchDigest:                       manifest.LaunchDigest,
		GeneratedAt:                        generatedAt.UTC(),
		UpdatedAt:                          manifest.UpdatedAt.UTC(),
	}
	for _, check := range validation.Checks {
		validation.CheckCount++
		switch check.Outcome {
		case SecureCellGovernmentAgentExecutionLaunchReceiptValidationFail:
			validation.FailCount++
		case SecureCellGovernmentAgentExecutionLaunchReceiptValidationWarn:
			validation.WarnCount++
		default:
			validation.PassCount++
		}
	}
	validation.Status = secureCellGovernmentAgentExecutionLaunchReceiptValidationStatus(validation)
	validation.ValidationDigest = secureCellGovernmentAgentExecutionLaunchReceiptValidationDigest(validation)
	validation.ValidationID = "government-agent-execution-launch-receipt-validation:" + validation.CellID + ":" + validation.ValidationDigest[:12]
	return validation
}

func secureCellGovernmentAgentExecutionLaunchReceiptManifestCheck(
	manifest SecureCellGovernmentAgentExecutionLaunchReceiptManifest,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchReceiptValidationCheck {
	outcome := SecureCellGovernmentAgentExecutionLaunchReceiptValidationPass
	detail := "Launch receipt manifest has at least one expected receipt requirement."
	remediation := ""
	if manifest.ReceiptRequirementCount == 0 || len(manifest.Requirements) == 0 {
		outcome = SecureCellGovernmentAgentExecutionLaunchReceiptValidationFail
		detail = "Launch receipt manifest has no expected receipt requirements."
		remediation = "Regenerate launch clearance and receipt manifest before launch."
	}
	return secureCellGovernmentAgentExecutionLaunchReceiptValidationCheck("", "", "MANIFEST_REQUIREMENTS_PRESENT", outcome, detail, remediation, generatedAt)
}

func secureCellGovernmentAgentExecutionLaunchReceiptRequirementChecks(
	requirement SecureCellGovernmentAgentExecutionLaunchReceiptRequirement,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchReceiptValidationCheck {
	checks := []SecureCellGovernmentAgentExecutionLaunchReceiptValidationCheck{
		secureCellGovernmentAgentExecutionLaunchReceiptRequirementDigestCheck(requirement, generatedAt),
		secureCellGovernmentAgentExecutionLaunchReceiptRequirementTextCheck(requirement.RequirementID, requirement.ReceiptType, "VALIDATION_RULE_PRESENT", requirement.ValidationRule, "Validation rule is present.", "Add a validation rule for this receipt requirement.", generatedAt),
		secureCellGovernmentAgentExecutionLaunchReceiptRequirementTextCheck(requirement.RequirementID, requirement.ReceiptType, "EXPECTED_ATTACHMENT_PRESENT", requirement.ExpectedAttachment, "Expected attachment type is present.", "Add an expected attachment type for this receipt requirement.", generatedAt),
		secureCellGovernmentAgentExecutionLaunchReceiptRequirementTextCheck(requirement.RequirementID, requirement.ReceiptType, "CLEARANCE_ITEM_DIGEST_PRESENT", requirement.ClearanceItemDigest, "Clearance item digest is present.", "Regenerate the launch clearance register before receipt intake.", generatedAt),
	}
	if requirement.ReceiptType != "remediation_receipt" {
		checks = append(checks, secureCellGovernmentAgentExecutionLaunchReceiptRequirementTextCheck(requirement.RequirementID, requirement.ReceiptType, "EVIDENCE_BINDING_PRESENT", requirement.EvidenceBindingID, "Evidence binding is present.", "Bind this receipt requirement to the launch evidence item.", generatedAt))
	}
	return checks
}

func secureCellGovernmentAgentExecutionLaunchReceiptRequirementDigestCheck(
	requirement SecureCellGovernmentAgentExecutionLaunchReceiptRequirement,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchReceiptValidationCheck {
	expectedDigest := secureCellGovernmentAgentExecutionLaunchReceiptRequirementDigest(requirement)
	outcome := SecureCellGovernmentAgentExecutionLaunchReceiptValidationPass
	detail := "Receipt requirement digest matches its recomputed evidence hash and bound ID."
	remediation := ""
	if strings.TrimSpace(requirement.RequirementDigest) == "" {
		outcome = SecureCellGovernmentAgentExecutionLaunchReceiptValidationFail
		detail = "Receipt requirement digest is missing."
		remediation = "Regenerate the launch receipt manifest."
	} else if requirement.RequirementDigest != expectedDigest {
		outcome = SecureCellGovernmentAgentExecutionLaunchReceiptValidationFail
		detail = "Receipt requirement digest does not match its recomputed evidence hash."
		remediation = "Regenerate the launch receipt manifest from current clearance items."
	} else if !strings.Contains(requirement.RequirementID, secureCellGovernmentAgentDigestPrefix(requirement.RequirementDigest)) {
		outcome = SecureCellGovernmentAgentExecutionLaunchReceiptValidationFail
		detail = "Receipt requirement ID is not bound to the digest prefix."
		remediation = "Regenerate the launch receipt manifest so requirement IDs carry digest prefixes."
	}
	return secureCellGovernmentAgentExecutionLaunchReceiptValidationCheck(requirement.RequirementID, requirement.ReceiptType, "REQUIREMENT_DIGEST_BOUND", outcome, detail, remediation, generatedAt)
}

func secureCellGovernmentAgentExecutionLaunchReceiptRequirementTextCheck(
	requirementID string,
	receiptType string,
	code string,
	value string,
	passDetail string,
	remediation string,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchReceiptValidationCheck {
	outcome := SecureCellGovernmentAgentExecutionLaunchReceiptValidationPass
	detail := passDetail
	if strings.TrimSpace(value) == "" {
		outcome = SecureCellGovernmentAgentExecutionLaunchReceiptValidationFail
		detail = strings.TrimSuffix(passDetail, ".") + " check failed."
	}
	return secureCellGovernmentAgentExecutionLaunchReceiptValidationCheck(requirementID, receiptType, code, outcome, detail, remediation, generatedAt)
}

func secureCellGovernmentAgentExecutionLaunchReceiptValidationCheck(
	requirementID string,
	receiptType string,
	code string,
	outcome SecureCellGovernmentAgentExecutionLaunchReceiptValidationOutcome,
	detail string,
	remediation string,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchReceiptValidationCheck {
	check := SecureCellGovernmentAgentExecutionLaunchReceiptValidationCheck{
		RequirementID: strings.TrimSpace(requirementID),
		ReceiptType:   strings.TrimSpace(receiptType),
		Code:          strings.TrimSpace(code),
		Outcome:       outcome,
		Detail:        strings.TrimSpace(detail),
		Remediation:   strings.TrimSpace(remediation),
		GeneratedAt:   generatedAt.UTC(),
	}
	core := struct {
		RequirementID string                                                           `json:"requirement_id,omitempty"`
		ReceiptType   string                                                           `json:"receipt_type,omitempty"`
		Code          string                                                           `json:"code"`
		Outcome       SecureCellGovernmentAgentExecutionLaunchReceiptValidationOutcome `json:"outcome"`
		Detail        string                                                           `json:"detail"`
		Remediation   string                                                           `json:"remediation,omitempty"`
	}{
		RequirementID: check.RequirementID,
		ReceiptType:   check.ReceiptType,
		Code:          check.Code,
		Outcome:       check.Outcome,
		Detail:        check.Detail,
		Remediation:   check.Remediation,
	}
	check.CheckID = "government-agent-execution-launch-receipt-check:" + EvidenceHash(core)[:12]
	return check
}

func secureCellGovernmentAgentExecutionLaunchReceiptValidationStatus(validation SecureCellGovernmentAgentExecutionLaunchReceiptValidation) SecureCellGovernmentAgentExecutionLaunchReceiptValidationStatus {
	if validation.FailCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchReceiptValidationFailed
	}
	if validation.ManifestStatus == SecureCellGovernmentAgentExecutionLaunchReceiptManifestBlocked || validation.BlockedReceiptCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchReceiptValidationBlocked
	}
	return SecureCellGovernmentAgentExecutionLaunchReceiptValidationReady
}

func secureCellGovernmentAgentExecutionLaunchReceiptValidationStatusRank(status SecureCellGovernmentAgentExecutionLaunchReceiptValidationStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchReceiptValidationFailed:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchReceiptValidationBlocked:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchReceiptValidationReady:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchReceiptValidationDigest(validation SecureCellGovernmentAgentExecutionLaunchReceiptValidation) string {
	checkIDs := make([]string, 0, len(validation.Checks))
	for _, check := range validation.Checks {
		checkIDs = append(checkIDs, check.CheckID)
	}
	core := struct {
		ManifestID             string                                                          `json:"manifest_id"`
		RegisterID             string                                                          `json:"register_id"`
		CellID                 string                                                          `json:"cell_id"`
		Status                 SecureCellGovernmentAgentExecutionLaunchReceiptValidationStatus `json:"status"`
		ManifestStatus         SecureCellGovernmentAgentExecutionLaunchReceiptManifestStatus   `json:"manifest_status"`
		CanAcceptReceipts      bool                                                            `json:"can_accept_receipts"`
		CanLaunchAfterReceipts bool                                                            `json:"can_launch_after_receipts"`
		CheckIDs               []string                                                        `json:"check_ids"`
		ManifestDigest         string                                                          `json:"manifest_digest"`
		RegisterDigest         string                                                          `json:"register_digest"`
		LaunchDigest           string                                                          `json:"launch_digest"`
	}{
		ManifestID:             validation.ManifestID,
		RegisterID:             validation.RegisterID,
		CellID:                 validation.CellID,
		Status:                 validation.Status,
		ManifestStatus:         validation.ManifestStatus,
		CanAcceptReceipts:      validation.CanAcceptReceipts,
		CanLaunchAfterReceipts: validation.CanLaunchAfterReceipts,
		CheckIDs:               checkIDs,
		ManifestDigest:         validation.ManifestDigest,
		RegisterDigest:         validation.RegisterDigest,
		LaunchDigest:           validation.LaunchDigest,
	}
	return EvidenceHash(core)
}
