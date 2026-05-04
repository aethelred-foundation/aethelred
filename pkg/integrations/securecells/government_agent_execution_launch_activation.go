package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchActivationStatus describes whether a
// custody-bound launch package can enter execution.
type SecureCellGovernmentAgentExecutionLaunchActivationStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchActivationDenied                   SecureCellGovernmentAgentExecutionLaunchActivationStatus = "activation_denied"
	SecureCellGovernmentAgentExecutionLaunchActivationOperatorReceiptsRequired SecureCellGovernmentAgentExecutionLaunchActivationStatus = "operator_receipts_required"
	SecureCellGovernmentAgentExecutionLaunchActivationActive                   SecureCellGovernmentAgentExecutionLaunchActivationStatus = "active_launch_window"
)

// SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus records one
// validation outcome for a launch activation certificate.
type SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus string

const (
	SecureCellGovernmentAgentExecutionLaunchActivationCheckPass SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus = "pass"
	SecureCellGovernmentAgentExecutionLaunchActivationCheckWarn SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus = "warn"
	SecureCellGovernmentAgentExecutionLaunchActivationCheckFail SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus = "fail"
)

// SecureCellGovernmentAgentExecutionLaunchActivationCheck is one computed
// guardrail for moving a launch package from custody into execution.
type SecureCellGovernmentAgentExecutionLaunchActivationCheck struct {
	CheckID        string                                                        `json:"check_id"`
	Code           string                                                        `json:"code"`
	Status         SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus `json:"status"`
	Detail         string                                                        `json:"detail"`
	Remediation    string                                                        `json:"remediation,omitempty"`
	EvidenceDigest string                                                        `json:"evidence_digest,omitempty"`
	CheckDigest    string                                                        `json:"check_digest"`
	GeneratedAt    time.Time                                                     `json:"generated_at"`
}

// SecureCellGovernmentAgentExecutionLaunchActivationCertificate is the final
// execution-start certificate derived from a launch custody register.
type SecureCellGovernmentAgentExecutionLaunchActivationCertificate struct {
	ActivationID                    string                                                    `json:"activation_id"`
	CustodyID                       string                                                    `json:"custody_id"`
	PackageID                       string                                                    `json:"package_id"`
	CellID                          string                                                    `json:"cell_id"`
	Name                            string                                                    `json:"name"`
	Jurisdiction                    string                                                    `json:"jurisdiction,omitempty"`
	ServiceCode                     string                                                    `json:"service_code,omitempty"`
	ServiceTier                     string                                                    `json:"service_tier,omitempty"`
	Status                          SecureCellGovernmentAgentExecutionLaunchActivationStatus  `json:"status"`
	CustodyStatus                   SecureCellGovernmentAgentExecutionLaunchCustodyStatus     `json:"custody_status"`
	PackageStatus                   SecureCellGovernmentAgentExecutionLaunchPackageStatus     `json:"package_status"`
	CanExecuteNow                   bool                                                      `json:"can_execute_now"`
	CanExecuteAfterOperatorReceipts bool                                                      `json:"can_execute_after_operator_receipts"`
	CanExecuteAutonomous            bool                                                      `json:"can_execute_autonomous"`
	LeaseMinutes                    int                                                       `json:"lease_minutes"`
	ActivationWindowStartsAt        time.Time                                                 `json:"activation_window_starts_at"`
	ActivationWindowExpiresAt       time.Time                                                 `json:"activation_window_expires_at"`
	CheckCount                      int                                                       `json:"check_count"`
	PassCount                       int                                                       `json:"pass_count"`
	WarnCount                       int                                                       `json:"warn_count"`
	FailCount                       int                                                       `json:"fail_count"`
	RequiredReceiptTypes            []string                                                  `json:"required_receipt_types,omitempty"`
	OperatorInstructions            []string                                                  `json:"operator_instructions,omitempty"`
	PackageDigest                   string                                                    `json:"package_digest"`
	CustodyDigest                   string                                                    `json:"custody_digest"`
	LaunchDigest                    string                                                    `json:"launch_digest"`
	ReceiptManifestDigest           string                                                    `json:"receipt_manifest_digest"`
	ReceiptValidationDigest         string                                                    `json:"receipt_validation_digest"`
	Checks                          []SecureCellGovernmentAgentExecutionLaunchActivationCheck `json:"checks"`
	Custody                         SecureCellGovernmentAgentExecutionLaunchCustodyRegister   `json:"custody"`
	ActivationDigest                string                                                    `json:"activation_digest"`
	GeneratedAt                     time.Time                                                 `json:"generated_at"`
	UpdatedAt                       time.Time                                                 `json:"updated_at"`
}

// GetGovernmentAgentExecutionLaunchActivation returns the activation certificate
// for one secure cell.
func (s *Service) GetGovernmentAgentExecutionLaunchActivation(ctx context.Context, cellID string) (*SecureCellGovernmentAgentExecutionLaunchActivationCertificate, error) {
	items, err := s.ListGovernmentAgentExecutionLaunchActivations(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID: strings.TrimSpace(cellID),
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-activation: %w: %q", ErrCellNotFound, strings.TrimSpace(cellID))
	}
	return &items[0], nil
}

// ListGovernmentAgentExecutionLaunchActivations returns activation certificates
// for matching government-service workflows.
func (s *Service) ListGovernmentAgentExecutionLaunchActivations(ctx context.Context, filter SecureCellGovernmentAgentProgramFilter) ([]SecureCellGovernmentAgentExecutionLaunchActivationCertificate, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-activation: service is required")
	}
	custodies, err := s.ListGovernmentAgentExecutionLaunchCustodies(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	certificates := make([]SecureCellGovernmentAgentExecutionLaunchActivationCertificate, 0, len(custodies))
	for _, custody := range custodies {
		certificates = append(certificates, secureCellGovernmentAgentExecutionLaunchActivationCertificate(custody, now))
	}
	sort.SliceStable(certificates, func(i, j int) bool {
		if certificates[i].Status == certificates[j].Status {
			if certificates[i].FailCount == certificates[j].FailCount {
				if certificates[i].WarnCount == certificates[j].WarnCount {
					return certificates[i].CellID < certificates[j].CellID
				}
				return certificates[i].WarnCount > certificates[j].WarnCount
			}
			return certificates[i].FailCount > certificates[j].FailCount
		}
		return secureCellGovernmentAgentExecutionLaunchActivationStatusRank(certificates[i].Status) < secureCellGovernmentAgentExecutionLaunchActivationStatusRank(certificates[j].Status)
	})
	return certificates, nil
}

func secureCellGovernmentAgentExecutionLaunchActivationCertificate(
	custody SecureCellGovernmentAgentExecutionLaunchCustodyRegister,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchActivationCertificate {
	checks := secureCellGovernmentAgentExecutionLaunchActivationChecks(custody, generatedAt)
	certificate := SecureCellGovernmentAgentExecutionLaunchActivationCertificate{
		CustodyID:                 custody.CustodyID,
		PackageID:                 custody.PackageID,
		CellID:                    custody.CellID,
		Name:                      custody.Name,
		Jurisdiction:              custody.Jurisdiction,
		ServiceCode:               custody.ServiceCode,
		ServiceTier:               custody.ServiceTier,
		CustodyStatus:             custody.Status,
		PackageStatus:             custody.PackageStatus,
		LeaseMinutes:              custody.LeaseMinutes,
		ActivationWindowStartsAt:  custody.ActivationWindowStartsAt.UTC(),
		ActivationWindowExpiresAt: custody.ActivationWindowExpiresAt.UTC(),
		RequiredReceiptTypes:      append([]string(nil), custody.RequiredReceiptTypes...),
		PackageDigest:             custody.PackageDigest,
		CustodyDigest:             custody.CustodyDigest,
		LaunchDigest:              custody.LaunchDigest,
		ReceiptManifestDigest:     custody.ReceiptManifestDigest,
		ReceiptValidationDigest:   custody.ReceiptValidationDigest,
		Checks:                    checks,
		Custody:                   custody,
		GeneratedAt:               generatedAt.UTC(),
		UpdatedAt:                 custody.UpdatedAt.UTC(),
	}
	for _, check := range certificate.Checks {
		certificate.CheckCount++
		switch check.Status {
		case SecureCellGovernmentAgentExecutionLaunchActivationCheckFail:
			certificate.FailCount++
		case SecureCellGovernmentAgentExecutionLaunchActivationCheckWarn:
			certificate.WarnCount++
		default:
			certificate.PassCount++
		}
	}
	certificate.Status = secureCellGovernmentAgentExecutionLaunchActivationStatus(certificate)
	certificate.CanExecuteNow = certificate.Status == SecureCellGovernmentAgentExecutionLaunchActivationActive && custody.CanIssueNow
	certificate.CanExecuteAfterOperatorReceipts = certificate.Status == SecureCellGovernmentAgentExecutionLaunchActivationOperatorReceiptsRequired && custody.CanIssueAfterOperatorReceipts
	certificate.CanExecuteAutonomous = certificate.CanExecuteNow && custody.CanIssueAutonomous
	certificate.OperatorInstructions = secureCellGovernmentAgentExecutionLaunchActivationInstructions(certificate)
	certificate.ActivationDigest = secureCellGovernmentAgentExecutionLaunchActivationDigest(certificate)
	certificate.ActivationID = "government-agent-execution-launch-activation:" + certificate.CellID + ":" + certificate.ActivationDigest[:12]
	return certificate
}

func secureCellGovernmentAgentExecutionLaunchActivationChecks(
	custody SecureCellGovernmentAgentExecutionLaunchCustodyRegister,
	generatedAt time.Time,
) []SecureCellGovernmentAgentExecutionLaunchActivationCheck {
	checks := []SecureCellGovernmentAgentExecutionLaunchActivationCheck{
		secureCellGovernmentAgentExecutionLaunchActivationCheck("CUSTODY_DIGEST_BOUND", secureCellGovernmentAgentExecutionLaunchActivationDigestBoundStatus(custody.CustodyID, custody.CustodyDigest), "Custody register ID must bind to the custody digest.", "Regenerate custody register before launch.", custody.CustodyDigest, generatedAt),
		secureCellGovernmentAgentExecutionLaunchActivationCheck("PACKAGE_DIGEST_BOUND", secureCellGovernmentAgentExecutionLaunchActivationDigestBoundStatus(custody.PackageID, custody.PackageDigest), "Launch package ID must bind to the package digest.", "Regenerate launch package before launch.", custody.PackageDigest, generatedAt),
		secureCellGovernmentAgentExecutionLaunchActivationCheck("RECEIPT_VALIDATION_BOUND", secureCellGovernmentAgentExecutionLaunchActivationNonEmptyStatus(custody.ReceiptValidationDigest), "Receipt validation digest must be present.", "Regenerate receipt validation before launch.", custody.ReceiptValidationDigest, generatedAt),
		secureCellGovernmentAgentExecutionLaunchActivationCheck("ACTIVATION_WINDOW_OPEN", secureCellGovernmentAgentExecutionLaunchActivationWindowStatus(custody, generatedAt), "Activation window must be open and unexpired.", "Regenerate custody register after the activation window expires.", custody.CustodyDigest, generatedAt),
		secureCellGovernmentAgentExecutionLaunchActivationCheck("CUSTODY_ACTIONS_CLEARED", secureCellGovernmentAgentExecutionLaunchActivationActionStatus(custody), "Custody actions must not contain unresolved blockers.", "Clear blocked or pending custody actions before execution.", custody.CustodyDigest, generatedAt),
		secureCellGovernmentAgentExecutionLaunchActivationCheck("PACKAGE_ISSUE_ALLOWED", secureCellGovernmentAgentExecutionLaunchActivationIssueStatus(custody), "Custody state must permit package issue.", "Collect required receipts or resolve the blocked package before issue.", custody.PackageDigest, generatedAt),
	}
	sort.SliceStable(checks, func(i, j int) bool {
		if checks[i].Status == checks[j].Status {
			return checks[i].Code < checks[j].Code
		}
		return secureCellGovernmentAgentExecutionLaunchActivationCheckStatusRank(checks[i].Status) < secureCellGovernmentAgentExecutionLaunchActivationCheckStatusRank(checks[j].Status)
	})
	return checks
}

func secureCellGovernmentAgentExecutionLaunchActivationCheck(
	code string,
	status SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus,
	detail string,
	remediation string,
	evidenceDigest string,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchActivationCheck {
	check := SecureCellGovernmentAgentExecutionLaunchActivationCheck{
		Code:           strings.TrimSpace(code),
		Status:         status,
		Detail:         strings.TrimSpace(detail),
		Remediation:    strings.TrimSpace(remediation),
		EvidenceDigest: strings.TrimSpace(evidenceDigest),
		GeneratedAt:    generatedAt.UTC(),
	}
	if check.Status == SecureCellGovernmentAgentExecutionLaunchActivationCheckPass {
		check.Remediation = ""
	}
	check.CheckDigest = secureCellGovernmentAgentExecutionLaunchActivationCheckDigest(check)
	check.CheckID = "government-agent-execution-launch-activation-check:" + check.CheckDigest[:12]
	return check
}

func secureCellGovernmentAgentExecutionLaunchActivationDigestBoundStatus(id string, digest string) SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus {
	trimmedDigest := strings.TrimSpace(digest)
	if trimmedDigest == "" || len(trimmedDigest) < 12 {
		return SecureCellGovernmentAgentExecutionLaunchActivationCheckFail
	}
	if !strings.Contains(strings.TrimSpace(id), trimmedDigest[:12]) {
		return SecureCellGovernmentAgentExecutionLaunchActivationCheckFail
	}
	return SecureCellGovernmentAgentExecutionLaunchActivationCheckPass
}

func secureCellGovernmentAgentExecutionLaunchActivationNonEmptyStatus(value string) SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus {
	if strings.TrimSpace(value) == "" {
		return SecureCellGovernmentAgentExecutionLaunchActivationCheckFail
	}
	return SecureCellGovernmentAgentExecutionLaunchActivationCheckPass
}

func secureCellGovernmentAgentExecutionLaunchActivationWindowStatus(
	custody SecureCellGovernmentAgentExecutionLaunchCustodyRegister,
	now time.Time,
) SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus {
	if custody.ActivationWindowStartsAt.IsZero() || custody.ActivationWindowExpiresAt.IsZero() {
		return SecureCellGovernmentAgentExecutionLaunchActivationCheckFail
	}
	if now.UTC().Before(custody.ActivationWindowStartsAt.UTC()) || !now.UTC().Before(custody.ActivationWindowExpiresAt.UTC()) {
		return SecureCellGovernmentAgentExecutionLaunchActivationCheckFail
	}
	return SecureCellGovernmentAgentExecutionLaunchActivationCheckPass
}

func secureCellGovernmentAgentExecutionLaunchActivationActionStatus(custody SecureCellGovernmentAgentExecutionLaunchCustodyRegister) SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus {
	if custody.BlockedActionCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchActivationCheckFail
	}
	if custody.PendingActionCount > 0 {
		return SecureCellGovernmentAgentExecutionLaunchActivationCheckWarn
	}
	return SecureCellGovernmentAgentExecutionLaunchActivationCheckPass
}

func secureCellGovernmentAgentExecutionLaunchActivationIssueStatus(custody SecureCellGovernmentAgentExecutionLaunchCustodyRegister) SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus {
	if custody.Status == SecureCellGovernmentAgentExecutionLaunchCustodyBlocked {
		return SecureCellGovernmentAgentExecutionLaunchActivationCheckFail
	}
	if custody.Status == SecureCellGovernmentAgentExecutionLaunchCustodyAwaitingReceipt {
		return SecureCellGovernmentAgentExecutionLaunchActivationCheckWarn
	}
	if custody.CanIssueNow {
		return SecureCellGovernmentAgentExecutionLaunchActivationCheckPass
	}
	return SecureCellGovernmentAgentExecutionLaunchActivationCheckFail
}

func secureCellGovernmentAgentExecutionLaunchActivationStatus(certificate SecureCellGovernmentAgentExecutionLaunchActivationCertificate) SecureCellGovernmentAgentExecutionLaunchActivationStatus {
	if certificate.FailCount > 0 || certificate.CustodyStatus == SecureCellGovernmentAgentExecutionLaunchCustodyBlocked {
		return SecureCellGovernmentAgentExecutionLaunchActivationDenied
	}
	if certificate.WarnCount > 0 || certificate.CustodyStatus == SecureCellGovernmentAgentExecutionLaunchCustodyAwaitingReceipt {
		return SecureCellGovernmentAgentExecutionLaunchActivationOperatorReceiptsRequired
	}
	return SecureCellGovernmentAgentExecutionLaunchActivationActive
}

func secureCellGovernmentAgentExecutionLaunchActivationInstructions(certificate SecureCellGovernmentAgentExecutionLaunchActivationCertificate) []string {
	instructions := append([]string(nil), certificate.Custody.OperatorInstructions...)
	switch certificate.Status {
	case SecureCellGovernmentAgentExecutionLaunchActivationDenied:
		instructions = append(instructions, "Do not execute until failed activation checks are corrected.")
	case SecureCellGovernmentAgentExecutionLaunchActivationOperatorReceiptsRequired:
		instructions = append(instructions, "Attach operator receipts and regenerate activation before execution.")
	default:
		instructions = append(instructions, "Execute only while the activation certificate remains inside its launch window.")
	}
	return uniqueSortedStrings(instructions)
}

func secureCellGovernmentAgentExecutionLaunchActivationStatusRank(status SecureCellGovernmentAgentExecutionLaunchActivationStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchActivationDenied:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchActivationOperatorReceiptsRequired:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchActivationActive:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchActivationCheckStatusRank(status SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus) int {
	switch status {
	case SecureCellGovernmentAgentExecutionLaunchActivationCheckFail:
		return 0
	case SecureCellGovernmentAgentExecutionLaunchActivationCheckWarn:
		return 1
	case SecureCellGovernmentAgentExecutionLaunchActivationCheckPass:
		return 2
	default:
		return 3
	}
}

func secureCellGovernmentAgentExecutionLaunchActivationCheckDigest(check SecureCellGovernmentAgentExecutionLaunchActivationCheck) string {
	core := struct {
		Code           string                                                        `json:"code"`
		Status         SecureCellGovernmentAgentExecutionLaunchActivationCheckStatus `json:"status"`
		Detail         string                                                        `json:"detail"`
		Remediation    string                                                        `json:"remediation,omitempty"`
		EvidenceDigest string                                                        `json:"evidence_digest,omitempty"`
	}{
		Code:           check.Code,
		Status:         check.Status,
		Detail:         check.Detail,
		Remediation:    check.Remediation,
		EvidenceDigest: check.EvidenceDigest,
	}
	return EvidenceHash(core)
}

func secureCellGovernmentAgentExecutionLaunchActivationDigest(certificate SecureCellGovernmentAgentExecutionLaunchActivationCertificate) string {
	checkDigests := make([]string, 0, len(certificate.Checks))
	for _, check := range certificate.Checks {
		checkDigests = append(checkDigests, check.CheckDigest)
	}
	core := struct {
		CustodyID                       string                                                   `json:"custody_id"`
		PackageID                       string                                                   `json:"package_id"`
		CellID                          string                                                   `json:"cell_id"`
		Status                          SecureCellGovernmentAgentExecutionLaunchActivationStatus `json:"status"`
		CustodyStatus                   SecureCellGovernmentAgentExecutionLaunchCustodyStatus    `json:"custody_status"`
		PackageStatus                   SecureCellGovernmentAgentExecutionLaunchPackageStatus    `json:"package_status"`
		CanExecuteNow                   bool                                                     `json:"can_execute_now"`
		CanExecuteAfterOperatorReceipts bool                                                     `json:"can_execute_after_operator_receipts"`
		CanExecuteAutonomous            bool                                                     `json:"can_execute_autonomous"`
		LeaseMinutes                    int                                                      `json:"lease_minutes"`
		CheckDigests                    []string                                                 `json:"check_digests,omitempty"`
		PackageDigest                   string                                                   `json:"package_digest"`
		CustodyDigest                   string                                                   `json:"custody_digest"`
		LaunchDigest                    string                                                   `json:"launch_digest"`
		ReceiptManifestDigest           string                                                   `json:"receipt_manifest_digest"`
		ReceiptValidationDigest         string                                                   `json:"receipt_validation_digest"`
	}{
		CustodyID:                       certificate.CustodyID,
		PackageID:                       certificate.PackageID,
		CellID:                          certificate.CellID,
		Status:                          certificate.Status,
		CustodyStatus:                   certificate.CustodyStatus,
		PackageStatus:                   certificate.PackageStatus,
		CanExecuteNow:                   certificate.CanExecuteNow,
		CanExecuteAfterOperatorReceipts: certificate.CanExecuteAfterOperatorReceipts,
		CanExecuteAutonomous:            certificate.CanExecuteAutonomous,
		LeaseMinutes:                    certificate.LeaseMinutes,
		CheckDigests:                    checkDigests,
		PackageDigest:                   certificate.PackageDigest,
		CustodyDigest:                   certificate.CustodyDigest,
		LaunchDigest:                    certificate.LaunchDigest,
		ReceiptManifestDigest:           certificate.ReceiptManifestDigest,
		ReceiptValidationDigest:         certificate.ReceiptValidationDigest,
	}
	return EvidenceHash(core)
}
