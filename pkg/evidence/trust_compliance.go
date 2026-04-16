package evidence

import (
	"fmt"
	"strings"
)

// TrustComplianceSignatureEvidence captures the detached signature metadata for
// an anchored trust-compliance export package.
type TrustComplianceSignatureEvidence struct {
	Signer    string `json:"signer"`
	KeyID     string `json:"key_id,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	SignedAt  string `json:"signed_at,omitempty"`
}

// TrustComplianceAuditAnchorEvidence captures the keeper audit record that
// anchored a trust-compliance export package into the network evidence trail.
type TrustComplianceAuditAnchorEvidence struct {
	Sequence     uint64 `json:"sequence"`
	RecordHash   string `json:"record_hash"`
	PreviousHash string `json:"previous_hash,omitempty"`
	Action       string `json:"action"`
	Actor        string `json:"actor,omitempty"`
	Timestamp    string `json:"timestamp"`
	BlockHeight  int64  `json:"block_height,omitempty"`
}

// TrustCompliancePackageEvidence is the canonical evidence-layer projection of
// a packaged PoUW trust-compliance export.
type TrustCompliancePackageEvidence struct {
	ID                   string                              `json:"id"`
	PackageHash          string                              `json:"package_hash"`
	PayloadHash          string                              `json:"payload_hash"`
	DocumentHash         string                              `json:"document_hash"`
	Format               string                              `json:"format"`
	ExportVersion        string                              `json:"export_version"`
	GeneratedAt          string                              `json:"generated_at"`
	TrustRegistryVersion string                              `json:"trust_registry_version,omitempty"`
	TrustRegistrySource  string                              `json:"trust_registry_source,omitempty"`
	BlockHeight          int64                               `json:"block_height,omitempty"`
	CurrentEpoch         uint64                              `json:"current_epoch,omitempty"`
	TotalUWU             uint64                              `json:"total_uwu,omitempty"`
	HistoryCount         int                                 `json:"history_count,omitempty"`
	ComplianceTotal      int                                 `json:"compliance_total_controls,omitempty"`
	ComplianceMapped     int                                 `json:"compliance_mapped_controls,omitempty"`
	ComplianceGap        int                                 `json:"compliance_gap_controls,omitempty"`
	CustodyEntries       int                                 `json:"custody_entries,omitempty"`
	VerificationKeyIDs   []string                            `json:"verification_key_ids,omitempty"`
	Signed               bool                                `json:"signed"`
	Signature            *TrustComplianceSignatureEvidence   `json:"signature,omitempty"`
	AuditAnchor          *TrustComplianceAuditAnchorEvidence `json:"audit_anchor,omitempty"`
	Metadata             map[string]string                   `json:"metadata,omitempty"`
}

// Normalize validates and fills deterministic defaults for trust-compliance
// package evidence.
func (tc *TrustCompliancePackageEvidence) Normalize() error {
	if tc == nil {
		return fmt.Errorf("evidence/trust_compliance: nil package evidence")
	}
	if strings.TrimSpace(tc.PackageHash) == "" {
		return fmt.Errorf("evidence/trust_compliance: package hash is required")
	}
	if strings.TrimSpace(tc.PayloadHash) == "" {
		return fmt.Errorf("evidence/trust_compliance: payload hash is required")
	}
	if strings.TrimSpace(tc.DocumentHash) == "" {
		return fmt.Errorf("evidence/trust_compliance: document hash is required")
	}
	if strings.TrimSpace(tc.Format) == "" {
		return fmt.Errorf("evidence/trust_compliance: format is required")
	}
	if strings.TrimSpace(tc.ExportVersion) == "" {
		return fmt.Errorf("evidence/trust_compliance: export version is required")
	}
	if strings.TrimSpace(tc.GeneratedAt) == "" {
		return fmt.Errorf("evidence/trust_compliance: generated_at is required")
	}
	if strings.TrimSpace(tc.ID) == "" {
		tc.ID = "trust-compliance-package:" + tc.PackageHash
	}
	tc.VerificationKeyIDs = cloneStringSlicePreserve(tc.VerificationKeyIDs)
	tc.Metadata = cloneStringMapPreserve(tc.Metadata)

	if tc.Signature != nil {
		if strings.TrimSpace(tc.Signature.Signer) == "" {
			return fmt.Errorf("evidence/trust_compliance: signature signer is required")
		}
		tc.Signed = true
	}
	if tc.Signed && tc.Signature == nil {
		return fmt.Errorf("evidence/trust_compliance: signed package must include signature metadata")
	}
	if tc.AuditAnchor != nil {
		if tc.AuditAnchor.Sequence == 0 {
			return fmt.Errorf("evidence/trust_compliance: audit anchor sequence is required")
		}
		if strings.TrimSpace(tc.AuditAnchor.RecordHash) == "" {
			return fmt.Errorf("evidence/trust_compliance: audit anchor record hash is required")
		}
		if strings.TrimSpace(tc.AuditAnchor.Action) == "" {
			return fmt.Errorf("evidence/trust_compliance: audit anchor action is required")
		}
		if tc.AuditAnchor.Action != "trust_compliance_export_anchored" {
			return fmt.Errorf("evidence/trust_compliance: unexpected audit anchor action %q", tc.AuditAnchor.Action)
		}
		if strings.TrimSpace(tc.AuditAnchor.Timestamp) == "" {
			return fmt.Errorf("evidence/trust_compliance: audit anchor timestamp is required")
		}
	}
	return nil
}

// AnchorRecordID returns the deterministic evidence-record ID used to project a
// trust-compliance package's audit anchor into the canonical record stream.
func (tc TrustCompliancePackageEvidence) AnchorRecordID() string {
	if strings.TrimSpace(tc.ID) != "" {
		return tc.ID + ":anchor"
	}
	if strings.TrimSpace(tc.PackageHash) != "" {
		return "trust-compliance-anchor:" + tc.PackageHash
	}
	return ""
}

// AnchorRecord projects the package's audit anchor into a canonical evidence
// record suitable for inclusion in an evidence bundle.
func (tc TrustCompliancePackageEvidence) AnchorRecord() (Record, error) {
	if err := (&tc).Normalize(); err != nil {
		return Record{}, err
	}
	if tc.AuditAnchor == nil {
		return Record{}, fmt.Errorf("evidence/trust_compliance: audit anchor is required")
	}
	record := Record{
		ID:          tc.AnchorRecordID(),
		Type:        "governance",
		Action:      tc.AuditAnchor.Action,
		Actor:       tc.AuditAnchor.Actor,
		Timestamp:   tc.AuditAnchor.Timestamp,
		BlockHeight: tc.AuditAnchor.BlockHeight,
		Data: map[string]string{
			"trust_compliance_package_id": tc.ID,
			"package_hash":                tc.PackageHash,
			"payload_hash":                tc.PayloadHash,
			"document_hash":               tc.DocumentHash,
			"audit_record_hash":           tc.AuditAnchor.RecordHash,
			"audit_sequence":              fmt.Sprintf("%d", tc.AuditAnchor.Sequence),
			"format":                      tc.Format,
			"export_version":              tc.ExportVersion,
		},
	}
	if tc.Signed {
		record.Data["signed"] = "true"
	}
	if tc.Signature != nil {
		record.Data["signer"] = tc.Signature.Signer
		if tc.Signature.KeyID != "" {
			record.Data["signature_key_id"] = tc.Signature.KeyID
		}
		if tc.Signature.Algorithm != "" {
			record.Data["signature_algorithm"] = tc.Signature.Algorithm
		}
	}
	record.Hash = record.ComputeHash()
	return record, nil
}
