package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PortableControlLedgerPackageSignature captures detached package-signing
// metadata for a portable control-ledger package.
type PortableControlLedgerPackageSignature struct {
	Algorithm string `json:"algorithm"`
	Signer    string `json:"signer"`
	KeyID     string `json:"key_id,omitempty"`
	Signature string `json:"signature"`
	SignedAt  string `json:"signed_at"`
}

// PortableControlLedgerPackageAuditAnchor captures the keeper governance audit
// record that anchored a portable control-ledger package into the audit chain.
type PortableControlLedgerPackageAuditAnchor struct {
	Sequence     uint64            `json:"sequence"`
	RecordHash   string            `json:"record_hash"`
	PreviousHash string            `json:"previous_hash,omitempty"`
	Category     string            `json:"category,omitempty"`
	Severity     string            `json:"severity,omitempty"`
	Action       string            `json:"action"`
	BlockHeight  int64             `json:"block_height,omitempty"`
	Timestamp    string            `json:"timestamp"`
	Actor        string            `json:"actor,omitempty"`
	Details      map[string]string `json:"details,omitempty"`
}

// PortableControlLedgerPackage is a self-contained, auditor-ready package for a
// validated control ledger. Unlike PortableEvidence, it preserves the full
// control mapping layer in addition to the underlying evidence bundle.
type PortableControlLedgerPackage struct {
	FormatVersion string         `json:"format_version"`
	PackagedAt    string         `json:"packaged_at"`
	Ledger        *ControlLedger `json:"ledger"`

	VerificationKeys []VerificationKey     `json:"verification_keys,omitempty"`
	TrustAnchors     []PlatformTrustAnchor `json:"trust_anchors,omitempty"`
	SchemaDefinition string                `json:"schema_definition,omitempty"`

	PackageHash string                                   `json:"package_hash"`
	AuditAnchor *PortableControlLedgerPackageAuditAnchor `json:"audit_anchor,omitempty"`
	Signature   *PortableControlLedgerPackageSignature   `json:"signature,omitempty"`
}

// PackagePortableControlLedger creates a portable auditor package from a
// validated control ledger.
func PackagePortableControlLedger(ledger *ControlLedger, includeVerificationKeys bool) (*PortableControlLedgerPackage, error) {
	if ledger == nil {
		return nil, fmt.Errorf("evidence/control_ledger_portable: nil control ledger")
	}

	cloned, err := cloneControlLedger(ledger)
	if err != nil {
		return nil, err
	}
	if cloned.Bundle != nil && cloned.Bundle.ContentHash == "" {
		if err := cloned.Finalize(""); err != nil {
			return nil, fmt.Errorf("evidence/control_ledger_portable: finalize cloned ledger: %w", err)
		}
	}
	if err := cloned.Validate(); err != nil {
		return nil, fmt.Errorf("evidence/control_ledger_portable: invalid control ledger: %w", err)
	}

	pkg := &PortableControlLedgerPackage{
		FormatVersion: "1.0.0",
		PackagedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Ledger:        cloned,
	}
	if includeVerificationKeys {
		pkg.SchemaDefinition = SchemaVersion
	}

	hash, err := pkg.computePackageHash()
	if err != nil {
		return nil, err
	}
	pkg.PackageHash = hash
	return pkg, nil
}

// VerifyPortableControlLedgerPackage verifies package integrity and the
// embedded ledger without network access.
func VerifyPortableControlLedgerPackage(pkg *PortableControlLedgerPackage) error {
	if pkg == nil {
		return fmt.Errorf("evidence/control_ledger_portable: nil package")
	}
	if pkg.Ledger == nil {
		return fmt.Errorf("evidence/control_ledger_portable: package contains no ledger")
	}

	computed, err := pkg.computePackageHash()
	if err != nil {
		return fmt.Errorf("evidence/control_ledger_portable: hash computation failed: %w", err)
	}
	if computed != pkg.PackageHash {
		return fmt.Errorf("evidence/control_ledger_portable: package hash mismatch")
	}
	if err := pkg.Ledger.Validate(); err != nil {
		return fmt.Errorf("evidence/control_ledger_portable: ledger validation failed: %w", err)
	}
	if err := verifyPortableBundleContext(pkg.Ledger.Bundle, pkg.TrustAnchors); err != nil {
		return fmt.Errorf("evidence/control_ledger_portable: %w", err)
	}
	if pkg.AuditAnchor != nil {
		expectedRecordHash := pkg.AuditAnchor.ComputeHash()
		if pkg.AuditAnchor.RecordHash != expectedRecordHash {
			return fmt.Errorf("evidence/control_ledger_portable: audit anchor hash mismatch")
		}
		if pkg.AuditAnchor.Action != "control_ledger_package_anchored" {
			return fmt.Errorf("evidence/control_ledger_portable: unexpected audit anchor action %q", pkg.AuditAnchor.Action)
		}
		expectedDetails := pkg.AnchorDetails()
		for key, value := range expectedDetails {
			if pkg.AuditAnchor.Details[key] != value {
				return fmt.Errorf("evidence/control_ledger_portable: audit anchor %s mismatch", key)
			}
		}
	}
	if pkg.Signature == nil {
		return nil
	}
	if pkg.Signature.Algorithm != "ed25519" {
		return fmt.Errorf("evidence/control_ledger_portable: unsupported signature algorithm %q", pkg.Signature.Algorithm)
	}
	publicKey, err := pkg.verificationKeyForSignature()
	if err != nil {
		return err
	}
	signature, err := hex.DecodeString(pkg.Signature.Signature)
	if err != nil {
		return fmt.Errorf("evidence/control_ledger_portable: decode signature: %w", err)
	}
	hashBytes, err := hex.DecodeString(pkg.PackageHash)
	if err != nil {
		return fmt.Errorf("evidence/control_ledger_portable: decode package hash: %w", err)
	}
	if !ed25519.Verify(publicKey, hashBytes, signature) {
		return fmt.Errorf("evidence/control_ledger_portable: signature verification failed")
	}
	return nil
}

// AddVerificationKey adds a verification key to the control-ledger package.
func (pkg *PortableControlLedgerPackage) AddVerificationKey(key VerificationKey) {
	pkg.VerificationKeys = append(pkg.VerificationKeys, key)
}

// AddTrustAnchor adds a platform trust anchor to the control-ledger package.
func (pkg *PortableControlLedgerPackage) AddTrustAnchor(anchor PlatformTrustAnchor) {
	pkg.TrustAnchors = append(pkg.TrustAnchors, anchor)
}

// SignEd25519 signs the current package hash and stores detached signature
// metadata plus the verification key required for offline verification.
func (pkg *PortableControlLedgerPackage) SignEd25519(privateKey ed25519.PrivateKey, signer string) error {
	if pkg == nil {
		return fmt.Errorf("evidence/control_ledger_portable: nil package")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("evidence/control_ledger_portable: invalid ed25519 private key length: got %d", len(privateKey))
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyHash := sha256.Sum256(publicKey)
	keyID := hex.EncodeToString(keyHash[:8])
	if strings.TrimSpace(signer) == "" {
		signer = "validator:" + keyID
	}

	pkg.VerificationKeys = []VerificationKey{{
		KeyID:     keyID,
		Algorithm: "ed25519",
		PublicKey: hex.EncodeToString(publicKey),
	}}

	hash, err := pkg.computePackageHash()
	if err != nil {
		return err
	}
	pkg.PackageHash = hash

	hashBytes, err := hex.DecodeString(pkg.PackageHash)
	if err != nil {
		return fmt.Errorf("evidence/control_ledger_portable: invalid package hash: %w", err)
	}
	signature := ed25519.Sign(privateKey, hashBytes)
	pkg.Signature = &PortableControlLedgerPackageSignature{
		Algorithm: "ed25519",
		Signer:    signer,
		KeyID:     keyID,
		Signature: hex.EncodeToString(signature),
		SignedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	return nil
}

// AnchorDetails returns the canonical audit-detail map that should be used
// when anchoring a portable control-ledger package into governance history.
func (pkg *PortableControlLedgerPackage) AnchorDetails() map[string]string {
	if pkg == nil {
		return map[string]string{
			"portable_control_ledger_package": "true",
		}
	}
	details := map[string]string{
		"package_hash":                    strings.TrimSpace(pkg.PackageHash),
		"format_version":                  strings.TrimSpace(pkg.FormatVersion),
		"packaged_at":                     strings.TrimSpace(pkg.PackagedAt),
		"signed":                          strconv.FormatBool(pkg.Signature != nil),
		"verification_key_count":          strconv.Itoa(len(pkg.VerificationKeys)),
		"trust_anchor_count":              strconv.Itoa(len(pkg.TrustAnchors)),
		"schema_definition":               strings.TrimSpace(pkg.SchemaDefinition),
		"portable_control_ledger_package": "true",
	}
	if pkg.Ledger == nil || pkg.Ledger.Bundle == nil {
		return details
	}
	details["ledger_id"] = pkg.Ledger.Bundle.ID
	details["framework"] = pkg.Ledger.Bundle.Framework
	details["bundle_content_hash"] = pkg.Ledger.Bundle.ContentHash
	details["controls_total"] = strconv.Itoa(pkg.Ledger.Summary.TotalControls)
	details["approver_attestations_total"] = strconv.Itoa(pkg.Ledger.Summary.TotalApproverAttestations)
	details["value_settlements_total"] = strconv.Itoa(pkg.Ledger.Summary.TotalValueSettlements)
	details["trust_compliance_packages_total"] = strconv.Itoa(pkg.Ledger.Summary.TotalTrustCompliancePackages)
	if pkg.Signature != nil {
		details["signer"] = pkg.Signature.Signer
		details["signature_key_id"] = pkg.Signature.KeyID
		details["signature_algorithm"] = pkg.Signature.Algorithm
		details["signed_at"] = pkg.Signature.SignedAt
	}
	return details
}

// Marshal serializes the portable control-ledger package to JSON.
func (pkg *PortableControlLedgerPackage) Marshal() ([]byte, error) {
	return json.MarshalIndent(pkg, "", "  ")
}

// Clone returns a defensive copy of the control ledger.
func (cl *ControlLedger) Clone() (*ControlLedger, error) {
	return cloneControlLedger(cl)
}

func (pkg *PortableControlLedgerPackage) computePackageHash() (string, error) {
	type hashable struct {
		FormatVersion    string                `json:"format_version"`
		PackagedAt       string                `json:"packaged_at"`
		Ledger           *ControlLedger        `json:"ledger"`
		VerificationKeys []VerificationKey     `json:"verification_keys,omitempty"`
		TrustAnchors     []PlatformTrustAnchor `json:"trust_anchors,omitempty"`
		SchemaDefinition string                `json:"schema_definition,omitempty"`
	}

	h := hashable{
		FormatVersion:    pkg.FormatVersion,
		PackagedAt:       pkg.PackagedAt,
		Ledger:           pkg.Ledger,
		VerificationKeys: pkg.VerificationKeys,
		TrustAnchors:     pkg.TrustAnchors,
		SchemaDefinition: pkg.SchemaDefinition,
	}

	data, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("evidence/control_ledger_portable: marshal failed: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (pkg *PortableControlLedgerPackage) verificationKeyForSignature() (ed25519.PublicKey, error) {
	if pkg.Signature == nil {
		return nil, fmt.Errorf("evidence/control_ledger_portable: package is unsigned")
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
			return nil, fmt.Errorf("evidence/control_ledger_portable: decode public key: %w", err)
		}
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("evidence/control_ledger_portable: invalid public key length: %d", len(publicKey))
		}
		return ed25519.PublicKey(publicKey), nil
	}
	return nil, fmt.Errorf("evidence/control_ledger_portable: verification key %q not found", pkg.Signature.KeyID)
}

// ComputeHash returns the deterministic audit-record hash for the anchor.
func (a *PortableControlLedgerPackageAuditAnchor) ComputeHash() string {
	if a == nil {
		return ""
	}
	canonical := fmt.Sprintf(
		"seq=%d|prev=%s|cat=%s|sev=%s|act=%s|height=%d|ts=%s|actor=%s",
		a.Sequence, a.PreviousHash, a.Category, a.Severity, a.Action,
		a.BlockHeight, a.Timestamp, a.Actor,
	)
	if len(a.Details) > 0 {
		for _, key := range sortedStringMapKeys(a.Details) {
			canonical += fmt.Sprintf("|%s=%s", key, a.Details[key])
		}
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func sortedStringMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		key := keys[i]
		j := i - 1
		for j >= 0 && keys[j] > key {
			keys[j+1] = keys[j]
			j--
		}
		keys[j+1] = key
	}
	return keys
}
