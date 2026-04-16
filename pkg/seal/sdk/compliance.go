package sdk

import (
	"encoding/json"
	"fmt"

	auditexport "github.com/aethelred/aethelred/pkg/audit/export"
	"github.com/aethelred/aethelred/pkg/evidence"
)

// NewTrustCompliancePackageAttachment converts a packaged PoUW trust
// compliance export into a JSON evidence attachment that can be stored
// alongside seals and other enterprise evidence.
func NewTrustCompliancePackageAttachment(pkg *auditexport.PouwTrustCompliancePackage) (EvidenceAttachment, error) {
	artifact, err := auditexport.ToEvidenceTrustCompliancePackage(pkg)
	if err != nil {
		return EvidenceAttachment{}, fmt.Errorf("NewTrustCompliancePackageAttachment: invalid trust compliance package: %w", err)
	}
	data, err := json.Marshal(artifact)
	if err != nil {
		return EvidenceAttachment{}, fmt.Errorf("NewTrustCompliancePackageAttachment: marshal package evidence: %w", err)
	}

	signer := artifact.TrustRegistrySource
	if artifact.Signature != nil && artifact.Signature.Signer != "" {
		signer = artifact.Signature.Signer
	}
	description := "PoUW trust compliance package"
	if artifact.Signature != nil {
		description = "Signed PoUW trust compliance package"
	}
	if artifact.AuditAnchor != nil {
		description = "Anchored " + description
	}

	return NewEvidenceAttachment(EvidenceTypeTrustCompliancePackage, data, signer, description, "application/json"), nil
}

// NewTrustComplianceDocumentAttachment converts a raw trust compliance export
// document into a JSON evidence attachment when a packaged envelope is not
// required.
func NewTrustComplianceDocumentAttachment(doc *auditexport.PouwTrustComplianceExport, signer string) (EvidenceAttachment, error) {
	if doc == nil {
		return EvidenceAttachment{}, fmt.Errorf("NewTrustComplianceDocumentAttachment: nil document")
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return EvidenceAttachment{}, fmt.Errorf("NewTrustComplianceDocumentAttachment: marshal document: %w", err)
	}
	return NewEvidenceAttachment(EvidenceTypeComplianceDoc, data, signer, "PoUW trust compliance document", "application/json"), nil
}

// NewTrustComplianceArtifactAttachment converts canonical evidence-layer trust
// compliance package evidence into a JSON seal attachment without requiring the
// original package envelope.
func NewTrustComplianceArtifactAttachment(artifact evidence.TrustCompliancePackageEvidence) (EvidenceAttachment, error) {
	if err := (&artifact).Normalize(); err != nil {
		return EvidenceAttachment{}, fmt.Errorf("NewTrustComplianceArtifactAttachment: invalid artifact: %w", err)
	}
	data, err := json.Marshal(artifact)
	if err != nil {
		return EvidenceAttachment{}, fmt.Errorf("NewTrustComplianceArtifactAttachment: marshal artifact: %w", err)
	}
	signer := artifact.TrustRegistrySource
	if artifact.Signature != nil && artifact.Signature.Signer != "" {
		signer = artifact.Signature.Signer
	}
	description := "Trust compliance package evidence"
	if artifact.AuditAnchor != nil {
		description = "Anchored trust compliance package evidence"
	}
	return NewEvidenceAttachment(EvidenceTypeTrustCompliancePackage, data, signer, description, "application/json"), nil
}
