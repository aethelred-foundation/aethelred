package export

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aethelred/aethelred/pkg/evidence"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

// PouwTrustComplianceExportAnchorSummary normalizes the important fields from a
// trust-compliance export anchor audit record so operator tooling does not need
// to reverse-engineer raw audit details.
type PouwTrustComplianceExportAnchorSummary struct {
	PackageHash          string `json:"package_hash"`
	PayloadHash          string `json:"payload_hash,omitempty"`
	DocumentHash         string `json:"document_hash,omitempty"`
	Format               string `json:"format,omitempty"`
	ExportVersion        string `json:"export_version,omitempty"`
	GeneratedAt          string `json:"generated_at,omitempty"`
	HistoryCount         int    `json:"history_count,omitempty"`
	Signed               bool   `json:"signed"`
	Signer               string `json:"signer,omitempty"`
	SignatureKeyID       string `json:"signature_key_id,omitempty"`
	SignatureAlgorithm   string `json:"signature_algorithm,omitempty"`
	SignedAt             string `json:"signed_at,omitempty"`
	CustodyEntries       int    `json:"custody_entries,omitempty"`
	TrustRegistryVersion string `json:"trust_registry_version,omitempty"`
	TrustRegistrySource  string `json:"trust_registry_source,omitempty"`
	ComplianceTotal      int    `json:"compliance_total_controls,omitempty"`
	ComplianceMapped     int    `json:"compliance_mapped_controls,omitempty"`
	ComplianceGap        int    `json:"compliance_gap_controls,omitempty"`
}

// PouwTrustComplianceExportAnchorRecord combines the original audit record with
// a normalized summary and any parse error encountered while decoding it.
type PouwTrustComplianceExportAnchorRecord struct {
	Record     pouwkeeper.AuditRecord                  `json:"record"`
	Summary    *PouwTrustComplianceExportAnchorSummary `json:"summary,omitempty"`
	ParseError string                                  `json:"parse_error,omitempty"`
}

// PouwTrustComplianceExportAnchorFilter provides structured filtering over
// normalized export-anchor summaries.
type PouwTrustComplianceExportAnchorFilter struct {
	Format      string `json:"format,omitempty"`
	Signer      string `json:"signer,omitempty"`
	PackageHash string `json:"package_hash,omitempty"`
	Signed      *bool  `json:"signed,omitempty"`
	Limit       int    `json:"limit,omitempty"`
	Offset      int    `json:"offset,omitempty"`
}

// PouwTrustComplianceExportAnchorsResponse is the public response shape for
// normalized anchored-export discovery.
type PouwTrustComplianceExportAnchorsResponse struct {
	Anchors []PouwTrustComplianceExportAnchorRecord `json:"anchors"`
	Total   int                                     `json:"total"`
}

// PouwTrustCompliancePackageSummary exposes the most important package
// identity, signature, and anchoring fields in a stable shape for APIs and
// CLI tooling.
type PouwTrustCompliancePackageSummary struct {
	Format                string `json:"format,omitempty"`
	ExportVersion         string `json:"export_version,omitempty"`
	GeneratedAt           string `json:"generated_at,omitempty"`
	PayloadHash           string `json:"payload_hash,omitempty"`
	DocumentHash          string `json:"document_hash,omitempty"`
	PackageHash           string `json:"package_hash,omitempty"`
	Signed                bool   `json:"signed"`
	Signer                string `json:"signer,omitempty"`
	SignatureKeyID        string `json:"signature_key_id,omitempty"`
	SignatureAlgorithm    string `json:"signature_algorithm,omitempty"`
	SignedAt              string `json:"signed_at,omitempty"`
	VerificationKeyCount  int    `json:"verification_key_count,omitempty"`
	CustodyEntries        int    `json:"custody_entries,omitempty"`
	HasAuditAnchor        bool   `json:"has_audit_anchor"`
	AuditAnchorAction     string `json:"audit_anchor_action,omitempty"`
	AuditAnchorSequence   uint64 `json:"audit_anchor_sequence,omitempty"`
	AuditAnchorRecordHash string `json:"audit_anchor_record_hash,omitempty"`
	TrustRegistryVersion  string `json:"trust_registry_version,omitempty"`
	TrustRegistrySource   string `json:"trust_registry_source,omitempty"`
	BlockHeight           int64  `json:"block_height,omitempty"`
	CurrentEpoch          uint64 `json:"current_epoch,omitempty"`
	TotalUWU              uint64 `json:"total_uwu,omitempty"`
	HistoryCount          int    `json:"history_count,omitempty"`
	ComplianceTotal       int    `json:"compliance_total_controls,omitempty"`
	ComplianceMapped      int    `json:"compliance_mapped_controls,omitempty"`
	ComplianceGap         int    `json:"compliance_gap_controls,omitempty"`
}

// PouwTrustCompliancePackageVerification captures package integrity results in
// a transport-friendly form.
type PouwTrustCompliancePackageVerification struct {
	Valid   bool                               `json:"valid"`
	Summary *PouwTrustCompliancePackageSummary `json:"summary,omitempty"`
	Errors  []string                           `json:"errors,omitempty"`
}

// PouwTrustCompliancePackageVerificationResponse extends verification with any
// matching on-node anchor records discovered by the caller.
type PouwTrustCompliancePackageVerificationResponse struct {
	Verification     *PouwTrustCompliancePackageVerification `json:"verification"`
	AnchorMatches    []PouwTrustComplianceExportAnchorRecord `json:"anchor_matches,omitempty"`
	AnchorMatchCount int                                     `json:"anchor_match_count,omitempty"`
}

// SummarizePouwTrustComplianceExportAnchor normalizes a trust-compliance export
// anchor audit record.
func SummarizePouwTrustComplianceExportAnchor(record pouwkeeper.AuditRecord) (*PouwTrustComplianceExportAnchorSummary, error) {
	if record.Action != "trust_compliance_export_anchored" {
		return nil, fmt.Errorf("export/pouw_trust_compliance_verification: unexpected anchor action %q", record.Action)
	}
	summary := &PouwTrustComplianceExportAnchorSummary{
		PackageHash:          strings.TrimSpace(record.Details["package_hash"]),
		PayloadHash:          strings.TrimSpace(record.Details["payload_hash"]),
		DocumentHash:         strings.TrimSpace(record.Details["document_hash"]),
		Format:               strings.TrimSpace(record.Details["format"]),
		ExportVersion:        strings.TrimSpace(record.Details["export_version"]),
		GeneratedAt:          strings.TrimSpace(record.Details["generated_at"]),
		Signed:               strings.EqualFold(strings.TrimSpace(record.Details["signed"]), "true"),
		Signer:               strings.TrimSpace(record.Details["signer"]),
		SignatureKeyID:       strings.TrimSpace(record.Details["signature_key_id"]),
		SignatureAlgorithm:   strings.TrimSpace(record.Details["signature_algorithm"]),
		SignedAt:             strings.TrimSpace(record.Details["signed_at"]),
		TrustRegistryVersion: strings.TrimSpace(record.Details["trust_registry_version"]),
		TrustRegistrySource:  strings.TrimSpace(record.Details["trust_registry_source"]),
	}
	if summary.PackageHash == "" {
		return nil, fmt.Errorf("export/pouw_trust_compliance_verification: anchor is missing package hash")
	}
	summary.HistoryCount = parsePouwAnchorInt(record.Details["history_count"])
	summary.CustodyEntries = parsePouwAnchorInt(record.Details["custody_entries"])
	summary.ComplianceTotal = parsePouwAnchorInt(record.Details["compliance_total_controls"])
	summary.ComplianceMapped = parsePouwAnchorInt(record.Details["compliance_mapped_controls"])
	summary.ComplianceGap = parsePouwAnchorInt(record.Details["compliance_gap_controls"])
	return summary, nil
}

// SummarizePouwTrustComplianceExportAnchors converts raw audit records into
// normalized anchor rows while preserving any parse failures.
func SummarizePouwTrustComplianceExportAnchors(records []pouwkeeper.AuditRecord) []PouwTrustComplianceExportAnchorRecord {
	anchors := make([]PouwTrustComplianceExportAnchorRecord, 0, len(records))
	for _, record := range records {
		anchor := PouwTrustComplianceExportAnchorRecord{Record: record}
		summary, err := SummarizePouwTrustComplianceExportAnchor(record)
		if err != nil {
			anchor.ParseError = err.Error()
		} else {
			anchor.Summary = summary
		}
		anchors = append(anchors, anchor)
	}
	return anchors
}

// FilterPouwTrustComplianceExportAnchors applies structured anchor filters and
// returns both the paginated slice and the total matched count.
func FilterPouwTrustComplianceExportAnchors(
	anchors []PouwTrustComplianceExportAnchorRecord,
	filter *PouwTrustComplianceExportAnchorFilter,
) ([]PouwTrustComplianceExportAnchorRecord, int) {
	if filter == nil {
		filter = &PouwTrustComplianceExportAnchorFilter{}
	}

	matched := make([]PouwTrustComplianceExportAnchorRecord, 0, len(anchors))
	for _, anchor := range anchors {
		if !matchPouwTrustComplianceExportAnchor(anchor, filter) {
			continue
		}
		matched = append(matched, anchor)
	}

	total := len(matched)
	if filter.Offset > 0 {
		if filter.Offset >= len(matched) {
			return nil, total
		}
		matched = matched[filter.Offset:]
	}
	if filter.Limit > 0 && len(matched) > filter.Limit {
		matched = matched[:filter.Limit]
	}
	return matched, total
}

// SummarizePouwTrustCompliancePackage produces a stable package summary for
// operator tooling and verification responses.
func SummarizePouwTrustCompliancePackage(pkg *PouwTrustCompliancePackage) *PouwTrustCompliancePackageSummary {
	if pkg == nil {
		return nil
	}
	summary := &PouwTrustCompliancePackageSummary{
		Format:               pkg.Manifest.Format,
		ExportVersion:        pkg.Manifest.ExportVersion,
		GeneratedAt:          pkg.Manifest.GeneratedAt,
		PayloadHash:          pkg.Manifest.PayloadHash,
		DocumentHash:         pkg.Manifest.DocumentHash,
		PackageHash:          pkg.Manifest.PackageHash,
		VerificationKeyCount: len(pkg.VerificationKeys),
		CustodyEntries:       len(pkg.ChainOfCustody),
		TrustRegistryVersion: pkg.Manifest.TrustRegistryVersion,
		TrustRegistrySource:  pkg.Manifest.TrustRegistrySource,
		BlockHeight:          pkg.Manifest.BlockHeight,
		CurrentEpoch:         pkg.Manifest.CurrentEpoch,
		TotalUWU:             pkg.Manifest.TotalUWU,
		HistoryCount:         pkg.Manifest.HistoryCount,
		ComplianceTotal:      pkg.Manifest.ComplianceTotal,
		ComplianceMapped:     pkg.Manifest.ComplianceMapped,
		ComplianceGap:        pkg.Manifest.ComplianceGap,
	}
	if pkg.Signature != nil {
		summary.Signed = true
		summary.Signer = pkg.Signature.Signer
		summary.SignatureKeyID = pkg.Signature.KeyID
		summary.SignatureAlgorithm = pkg.Signature.Algorithm
		summary.SignedAt = pkg.Signature.SignedAt
	}
	if pkg.AuditAnchor != nil {
		summary.HasAuditAnchor = true
		summary.AuditAnchorAction = pkg.AuditAnchor.Action
		summary.AuditAnchorSequence = pkg.AuditAnchor.Sequence
		summary.AuditAnchorRecordHash = pkg.AuditAnchor.RecordHash
	}
	return summary
}

// VerifyPouwTrustCompliancePackageDetailed verifies a package and preserves the
// result in a structured transport-friendly form.
func VerifyPouwTrustCompliancePackageDetailed(pkg *PouwTrustCompliancePackage) *PouwTrustCompliancePackageVerification {
	result := &PouwTrustCompliancePackageVerification{
		Summary: SummarizePouwTrustCompliancePackage(pkg),
	}
	if pkg == nil {
		result.Errors = []string{"export/pouw_trust_compliance_package: nil package"}
		return result
	}
	if err := VerifyPouwTrustCompliancePackage(pkg); err != nil {
		result.Errors = []string{err.Error()}
		return result
	}
	result.Valid = true
	return result
}

// ToEvidenceTrustCompliancePackage converts a verified trust-compliance package
// into the canonical evidence-layer artifact used by evidence bundles and
// control ledgers.
func ToEvidenceTrustCompliancePackage(pkg *PouwTrustCompliancePackage) (evidence.TrustCompliancePackageEvidence, error) {
	if err := VerifyPouwTrustCompliancePackage(pkg); err != nil {
		return evidence.TrustCompliancePackageEvidence{}, fmt.Errorf("export/pouw_trust_compliance_verification: invalid package: %w", err)
	}
	if pkg == nil {
		return evidence.TrustCompliancePackageEvidence{}, fmt.Errorf("export/pouw_trust_compliance_verification: nil package")
	}

	artifact := evidence.TrustCompliancePackageEvidence{
		PackageHash:          pkg.Manifest.PackageHash,
		PayloadHash:          pkg.Manifest.PayloadHash,
		DocumentHash:         pkg.Manifest.DocumentHash,
		Format:               pkg.Manifest.Format,
		ExportVersion:        pkg.Manifest.ExportVersion,
		GeneratedAt:          pkg.Manifest.GeneratedAt,
		TrustRegistryVersion: pkg.Manifest.TrustRegistryVersion,
		TrustRegistrySource:  pkg.Manifest.TrustRegistrySource,
		BlockHeight:          pkg.Manifest.BlockHeight,
		CurrentEpoch:         pkg.Manifest.CurrentEpoch,
		TotalUWU:             pkg.Manifest.TotalUWU,
		HistoryCount:         pkg.Manifest.HistoryCount,
		ComplianceTotal:      pkg.Manifest.ComplianceTotal,
		ComplianceMapped:     pkg.Manifest.ComplianceMapped,
		ComplianceGap:        pkg.Manifest.ComplianceGap,
		CustodyEntries:       len(pkg.ChainOfCustody),
		Signed:               pkg.Signature != nil,
		VerificationKeyIDs:   make([]string, 0, len(pkg.VerificationKeys)),
		Metadata: map[string]string{
			"mime_type":        pkg.Manifest.MimeType,
			"payload_encoding": pkg.PayloadEncoding,
		},
	}
	for _, key := range pkg.VerificationKeys {
		if strings.TrimSpace(key.KeyID) != "" {
			artifact.VerificationKeyIDs = append(artifact.VerificationKeyIDs, key.KeyID)
		}
	}
	if pkg.Signature != nil {
		artifact.Signature = &evidence.TrustComplianceSignatureEvidence{
			Signer:    pkg.Signature.Signer,
			KeyID:     pkg.Signature.KeyID,
			Algorithm: pkg.Signature.Algorithm,
			SignedAt:  pkg.Signature.SignedAt,
		}
	}
	if pkg.AuditAnchor != nil {
		artifact.AuditAnchor = &evidence.TrustComplianceAuditAnchorEvidence{
			Sequence:     pkg.AuditAnchor.Sequence,
			RecordHash:   pkg.AuditAnchor.RecordHash,
			PreviousHash: pkg.AuditAnchor.PreviousHash,
			Action:       pkg.AuditAnchor.Action,
			Actor:        pkg.AuditAnchor.Actor,
			Timestamp:    pkg.AuditAnchor.Timestamp,
			BlockHeight:  pkg.AuditAnchor.BlockHeight,
		}
	}
	if err := artifact.Normalize(); err != nil {
		return evidence.TrustCompliancePackageEvidence{}, err
	}
	return artifact, nil
}

func matchPouwTrustComplianceExportAnchor(
	anchor PouwTrustComplianceExportAnchorRecord,
	filter *PouwTrustComplianceExportAnchorFilter,
) bool {
	if filter == nil {
		return true
	}
	if summary := anchor.Summary; summary != nil {
		if format := strings.TrimSpace(filter.Format); format != "" && !strings.EqualFold(summary.Format, format) {
			return false
		}
		if signer := strings.TrimSpace(filter.Signer); signer != "" && summary.Signer != signer {
			return false
		}
		if packageHash := strings.TrimSpace(filter.PackageHash); packageHash != "" && summary.PackageHash != packageHash {
			return false
		}
		if filter.Signed != nil && summary.Signed != *filter.Signed {
			return false
		}
		return true
	}

	// If the anchor could not be parsed, only include it when no structured
	// anchor filters were requested.
	return strings.TrimSpace(filter.Format) == "" &&
		strings.TrimSpace(filter.Signer) == "" &&
		strings.TrimSpace(filter.PackageHash) == "" &&
		filter.Signed == nil
}

func parsePouwAnchorInt(raw string) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 0 {
		return 0
	}
	return value
}
