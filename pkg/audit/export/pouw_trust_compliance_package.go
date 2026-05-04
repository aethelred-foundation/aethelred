package export

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	auditpkg "github.com/aethelred/aethelred/pkg/audit"
	"github.com/aethelred/aethelred/pkg/evidence"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

type PouwTrustCompliancePackageManifest struct {
	Format               string `json:"format"`
	MimeType             string `json:"mime_type"`
	ExportVersion        string `json:"export_version"`
	GeneratedAt          string `json:"generated_at"`
	PayloadHash          string `json:"payload_hash"`
	DocumentHash         string `json:"document_hash"`
	PackageHash          string `json:"package_hash"`
	TrustRegistryVersion string `json:"trust_registry_version,omitempty"`
	TrustRegistrySource  string `json:"trust_registry_source,omitempty"`
	BlockHeight          int64  `json:"block_height,omitempty"`
	CurrentEpoch         uint64 `json:"current_epoch,omitempty"`
	TotalUWU             uint64 `json:"total_uwu,omitempty"`
	HistoryCount         int    `json:"history_count,omitempty"`
	ComplianceTotal      int    `json:"compliance_total_controls,omitempty"`
	ComplianceMapped     int    `json:"compliance_mapped_controls,omitempty"`
	ComplianceGap        int    `json:"compliance_gap_controls,omitempty"`
}

type PouwTrustCompliancePackageSignature struct {
	Algorithm string `json:"algorithm"`
	Signer    string `json:"signer"`
	KeyID     string `json:"key_id,omitempty"`
	Signature string `json:"signature"`
	SignedAt  string `json:"signed_at"`
}

type PouwTrustCompliancePackage struct {
	Manifest         PouwTrustCompliancePackageManifest   `json:"manifest"`
	Document         *PouwTrustComplianceExport           `json:"document"`
	PayloadEncoding  string                               `json:"payload_encoding"`
	Payload          string                               `json:"payload"`
	ChainOfCustody   []evidence.CustodyEntry              `json:"chain_of_custody,omitempty"`
	VerificationKeys []evidence.VerificationKey           `json:"verification_keys,omitempty"`
	AuditAnchor      *pouwkeeper.AuditRecord              `json:"audit_anchor,omitempty"`
	Signature        *PouwTrustCompliancePackageSignature `json:"signature,omitempty"`
}

func CreatePouwTrustCompliancePackage(doc *PouwTrustComplianceExport, format string, payload []byte) (*PouwTrustCompliancePackage, error) {
	if doc == nil {
		return nil, fmt.Errorf("export/pouw_trust_compliance_package: nil document")
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("export/pouw_trust_compliance_package: payload cannot be empty")
	}

	normalizedFormat, err := NormalizePouwTrustComplianceFormat(format)
	if err != nil {
		return nil, err
	}

	documentHash, err := computePouwTrustComplianceDocumentHash(doc)
	if err != nil {
		return nil, err
	}
	payloadHash := sha256.Sum256(payload)

	pkg := &PouwTrustCompliancePackage{
		Manifest: PouwTrustCompliancePackageManifest{
			Format:        normalizedFormat,
			MimeType:      pouwTrustComplianceMimeType(normalizedFormat),
			ExportVersion: doc.ExportVersion,
			GeneratedAt:   doc.GeneratedAt,
			PayloadHash:   hex.EncodeToString(payloadHash[:]),
			DocumentHash:  documentHash,
			HistoryCount:  len(doc.History),
		},
		Document:        doc,
		PayloadEncoding: "base64",
		Payload:         base64.StdEncoding.EncodeToString(payload),
	}
	custodian := pouwTrustComplianceCustodian(doc)
	chain, err := buildPouwTrustComplianceCustodyChain(custodian, doc.GeneratedAt)
	if err != nil {
		return nil, err
	}
	pkg.ChainOfCustody = chain

	if doc.TrustRegistryStatus != nil {
		pkg.Manifest.TrustRegistryVersion = doc.TrustRegistryStatus.Version
		pkg.Manifest.TrustRegistrySource = doc.TrustRegistryStatus.Source
	}
	if doc.ModuleStatus != nil {
		pkg.Manifest.BlockHeight = doc.ModuleStatus.BlockHeight
		pkg.Manifest.CurrentEpoch = doc.ModuleStatus.CurrentEpoch
		pkg.Manifest.TotalUWU = doc.ModuleStatus.TotalUWU
	}
	if doc.ComplianceSummary != nil {
		pkg.Manifest.ComplianceTotal = doc.ComplianceSummary.TotalControls
		pkg.Manifest.ComplianceMapped = doc.ComplianceSummary.MappedControls
		pkg.Manifest.ComplianceGap = doc.ComplianceSummary.GapControls
	}

	hash, err := pkg.computePackageHash()
	if err != nil {
		return nil, err
	}
	pkg.Manifest.PackageHash = hash

	return pkg, nil
}

func (pkg *PouwTrustCompliancePackage) Marshal() ([]byte, error) {
	if pkg == nil {
		return nil, fmt.Errorf("export/pouw_trust_compliance_package: nil package")
	}
	return json.MarshalIndent(pkg, "", "  ")
}

func (pkg *PouwTrustCompliancePackage) PayloadBytes() ([]byte, error) {
	if pkg == nil {
		return nil, fmt.Errorf("export/pouw_trust_compliance_package: nil package")
	}
	if strings.TrimSpace(pkg.PayloadEncoding) != "base64" {
		return nil, fmt.Errorf("export/pouw_trust_compliance_package: unsupported payload encoding %q", pkg.PayloadEncoding)
	}
	payload, err := base64.StdEncoding.DecodeString(pkg.Payload)
	if err != nil {
		return nil, fmt.Errorf("export/pouw_trust_compliance_package: decode payload: %w", err)
	}
	return payload, nil
}

func (pkg *PouwTrustCompliancePackage) SignEd25519(privateKey ed25519.PrivateKey, signer string) error {
	if pkg == nil {
		return fmt.Errorf("export/pouw_trust_compliance_package: nil package")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("export/pouw_trust_compliance_package: invalid ed25519 private key length: got %d", len(privateKey))
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyHash := sha256.Sum256(publicKey)
	keyID := hex.EncodeToString(keyHash[:8])
	if strings.TrimSpace(signer) == "" {
		signer = "validator:" + keyID
	}

	pkg.VerificationKeys = []evidence.VerificationKey{{
		KeyID:     keyID,
		Algorithm: "ed25519",
		PublicKey: hex.EncodeToString(publicKey),
	}}

	hash, err := pkg.computePackageHash()
	if err != nil {
		return err
	}
	pkg.Manifest.PackageHash = hash

	hashBytes, err := hex.DecodeString(pkg.Manifest.PackageHash)
	if err != nil {
		return fmt.Errorf("export/pouw_trust_compliance_package: invalid package hash: %w", err)
	}

	signature := ed25519.Sign(privateKey, hashBytes)
	pkg.Signature = &PouwTrustCompliancePackageSignature{
		Algorithm: "ed25519",
		Signer:    signer,
		KeyID:     keyID,
		Signature: hex.EncodeToString(signature),
		SignedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}

	return nil
}

func VerifyPouwTrustCompliancePackage(pkg *PouwTrustCompliancePackage) error {
	if pkg == nil {
		return fmt.Errorf("export/pouw_trust_compliance_package: nil package")
	}
	if pkg.Document == nil {
		return fmt.Errorf("export/pouw_trust_compliance_package: document is required")
	}

	payload, err := pkg.PayloadBytes()
	if err != nil {
		return err
	}
	payloadHash := sha256.Sum256(payload)
	if got := hex.EncodeToString(payloadHash[:]); pkg.Manifest.PayloadHash != got {
		return fmt.Errorf("export/pouw_trust_compliance_package: payload hash mismatch")
	}

	documentHash, err := computePouwTrustComplianceDocumentHash(pkg.Document)
	if err != nil {
		return err
	}
	if pkg.Manifest.DocumentHash != documentHash {
		return fmt.Errorf("export/pouw_trust_compliance_package: document hash mismatch")
	}

	computedPackageHash, err := pkg.computePackageHash()
	if err != nil {
		return err
	}
	if pkg.Manifest.PackageHash != computedPackageHash {
		return fmt.Errorf("export/pouw_trust_compliance_package: package hash mismatch")
	}
	if len(pkg.ChainOfCustody) > 0 {
		if err := evidence.VerifyCustodyChain(pkg.ChainOfCustody); err != nil {
			return fmt.Errorf("export/pouw_trust_compliance_package: invalid chain of custody: %w", err)
		}
	}
	if pkg.AuditAnchor != nil {
		expectedRecordHash := auditpkg.ComputeRecordHash(*pkg.AuditAnchor)
		if pkg.AuditAnchor.RecordHash != expectedRecordHash {
			return fmt.Errorf("export/pouw_trust_compliance_package: audit anchor hash mismatch")
		}
		if pkg.AuditAnchor.Action != "trust_compliance_export_anchored" {
			return fmt.Errorf("export/pouw_trust_compliance_package: unexpected audit anchor action %q", pkg.AuditAnchor.Action)
		}
		if pkg.AuditAnchor.Details["package_hash"] != pkg.Manifest.PackageHash {
			return fmt.Errorf("export/pouw_trust_compliance_package: audit anchor package hash mismatch")
		}
		if pkg.AuditAnchor.Details["payload_hash"] != pkg.Manifest.PayloadHash {
			return fmt.Errorf("export/pouw_trust_compliance_package: audit anchor payload hash mismatch")
		}
		if pkg.AuditAnchor.Details["document_hash"] != pkg.Manifest.DocumentHash {
			return fmt.Errorf("export/pouw_trust_compliance_package: audit anchor document hash mismatch")
		}
	}

	if pkg.Signature == nil {
		return nil
	}
	if pkg.Signature.Algorithm != "ed25519" {
		return fmt.Errorf("export/pouw_trust_compliance_package: unsupported signature algorithm %q", pkg.Signature.Algorithm)
	}

	publicKey, err := pkg.verificationKeyForSignature()
	if err != nil {
		return err
	}
	signature, err := hex.DecodeString(pkg.Signature.Signature)
	if err != nil {
		return fmt.Errorf("export/pouw_trust_compliance_package: decode signature: %w", err)
	}
	hashBytes, err := hex.DecodeString(pkg.Manifest.PackageHash)
	if err != nil {
		return fmt.Errorf("export/pouw_trust_compliance_package: decode package hash: %w", err)
	}
	if !ed25519.Verify(publicKey, hashBytes, signature) {
		return fmt.Errorf("export/pouw_trust_compliance_package: signature verification failed")
	}

	return nil
}

func (pkg *PouwTrustCompliancePackage) verificationKeyForSignature() (ed25519.PublicKey, error) {
	if pkg.Signature == nil {
		return nil, fmt.Errorf("export/pouw_trust_compliance_package: package is unsigned")
	}
	for _, key := range pkg.VerificationKeys {
		if key.Algorithm != "ed25519" {
			continue
		}
		if pkg.Signature.KeyID != "" && key.KeyID != pkg.Signature.KeyID {
			continue
		}
		publicKey, err := hex.DecodeString(key.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("export/pouw_trust_compliance_package: decode public key: %w", err)
		}
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("export/pouw_trust_compliance_package: invalid public key length: got %d", len(publicKey))
		}
		return ed25519.PublicKey(publicKey), nil
	}
	return nil, fmt.Errorf("export/pouw_trust_compliance_package: no matching verification key found")
}

func (pkg *PouwTrustCompliancePackage) computePackageHash() (string, error) {
	type hashableManifest struct {
		Format               string `json:"format"`
		MimeType             string `json:"mime_type"`
		ExportVersion        string `json:"export_version"`
		GeneratedAt          string `json:"generated_at"`
		PayloadHash          string `json:"payload_hash"`
		DocumentHash         string `json:"document_hash"`
		TrustRegistryVersion string `json:"trust_registry_version,omitempty"`
		TrustRegistrySource  string `json:"trust_registry_source,omitempty"`
		BlockHeight          int64  `json:"block_height,omitempty"`
		CurrentEpoch         uint64 `json:"current_epoch,omitempty"`
		TotalUWU             uint64 `json:"total_uwu,omitempty"`
		HistoryCount         int    `json:"history_count,omitempty"`
		ComplianceTotal      int    `json:"compliance_total_controls,omitempty"`
		ComplianceMapped     int    `json:"compliance_mapped_controls,omitempty"`
		ComplianceGap        int    `json:"compliance_gap_controls,omitempty"`
	}
	type hashablePackage struct {
		Manifest         hashableManifest           `json:"manifest"`
		Document         *PouwTrustComplianceExport `json:"document"`
		PayloadEncoding  string                     `json:"payload_encoding"`
		Payload          string                     `json:"payload"`
		ChainOfCustody   []evidence.CustodyEntry    `json:"chain_of_custody,omitempty"`
		VerificationKeys []evidence.VerificationKey `json:"verification_keys,omitempty"`
	}

	payload := hashablePackage{
		Manifest: hashableManifest{
			Format:               pkg.Manifest.Format,
			MimeType:             pkg.Manifest.MimeType,
			ExportVersion:        pkg.Manifest.ExportVersion,
			GeneratedAt:          pkg.Manifest.GeneratedAt,
			PayloadHash:          pkg.Manifest.PayloadHash,
			DocumentHash:         pkg.Manifest.DocumentHash,
			TrustRegistryVersion: pkg.Manifest.TrustRegistryVersion,
			TrustRegistrySource:  pkg.Manifest.TrustRegistrySource,
			BlockHeight:          pkg.Manifest.BlockHeight,
			CurrentEpoch:         pkg.Manifest.CurrentEpoch,
			TotalUWU:             pkg.Manifest.TotalUWU,
			HistoryCount:         pkg.Manifest.HistoryCount,
			ComplianceTotal:      pkg.Manifest.ComplianceTotal,
			ComplianceMapped:     pkg.Manifest.ComplianceMapped,
			ComplianceGap:        pkg.Manifest.ComplianceGap,
		},
		Document:         pkg.Document,
		PayloadEncoding:  pkg.PayloadEncoding,
		Payload:          pkg.Payload,
		ChainOfCustody:   pkg.ChainOfCustody,
		VerificationKeys: pkg.VerificationKeys,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("export/pouw_trust_compliance_package: marshal hashable package: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func computePouwTrustComplianceDocumentHash(doc *PouwTrustComplianceExport) (string, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("export/pouw_trust_compliance_package: marshal document: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func pouwTrustComplianceMimeType(format string) string {
	switch format {
	case "csv":
		return "text/csv"
	default:
		return "application/json"
	}
}

func pouwTrustComplianceCustodian(doc *PouwTrustComplianceExport) string {
	if doc != nil && doc.TrustRegistryStatus != nil && strings.TrimSpace(doc.TrustRegistryStatus.Source) != "" {
		return doc.TrustRegistryStatus.Source
	}
	if doc != nil && doc.TrustRegistry != nil && strings.TrimSpace(doc.TrustRegistry.Source) != "" {
		return doc.TrustRegistry.Source
	}
	return "pouw_trust_control_plane"
}

func buildPouwTrustComplianceCustodyChain(custodian, generatedAt string) ([]evidence.CustodyEntry, error) {
	if strings.TrimSpace(custodian) == "" {
		return nil, fmt.Errorf("export/pouw_trust_compliance_package: custody custodian is required")
	}

	baseTime := time.Now().UTC()
	if parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(generatedAt)); err == nil && !parsed.IsZero() {
		baseTime = parsed.UTC()
	}

	created := evidence.CustodyEntry{
		Custodian:    custodian,
		Action:       "created",
		Timestamp:    formatPouwCustodyTimestamp(baseTime),
		PreviousHash: "",
	}
	created.Hash = created.ComputeHash()

	exported := evidence.CustodyEntry{
		Custodian:    custodian,
		Action:       "export",
		Timestamp:    formatPouwCustodyTimestamp(baseTime.Add(time.Nanosecond)),
		PreviousHash: created.Hash,
	}
	exported.Hash = exported.ComputeHash()

	return []evidence.CustodyEntry{created, exported}, nil
}

func formatPouwCustodyTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
}
