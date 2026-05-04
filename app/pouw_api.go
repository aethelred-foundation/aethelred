package app

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	audithttp "github.com/aethelred/aethelred/pkg/audit"
	auditexport "github.com/aethelred/aethelred/pkg/audit/export"
	"github.com/aethelred/aethelred/pkg/evidence"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type pouwAPIErrorResponse struct {
	Error string `json:"error"`
}

type pouwTrustRegistryResponse struct {
	Configured bool                                           `json:"configured"`
	Status     *pouwkeeper.EnterpriseAuditTrustRegistryStatus `json:"status,omitempty"`
	Registry   *pouwkeeper.EnterpriseAuditTrustRegistry       `json:"registry,omitempty"`
}

type pouwTrustCompliancePackageVerifyResponse = auditexport.PouwTrustCompliancePackageVerificationResponse
type pouwPortableControlLedgerPackageVerifyResponse = audithttp.VerifyPortableControlLedgerPackageResponse

// PouwModuleStatusHandler exposes keeper-backed PoUW module status for
// operator dashboards and CLI tooling without requiring protobuf changes.
func (app *AethelredApp) PouwModuleStatusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writePouwAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		ctx := safeAuditKeeperContext(app)
		if ctx == nil {
			writePouwAPIError(w, http.StatusServiceUnavailable, "pouw module status is unavailable")
			return
		}

		status, err := app.PouwKeeper.GetModuleStatus(ctx)
		if err != nil {
			writePouwAPIError(w, http.StatusInternalServerError, "failed to load pouw module status: "+err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(status)
	})
}

// PouwTrustRegistryHandler exposes the normalized enterprise trust registry for
// operator inspection without requiring access to audit admin APIs.
func (app *AethelredApp) PouwTrustRegistryHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writePouwAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		ctx := safeAuditKeeperContext(app)
		if ctx == nil {
			writePouwAPIError(w, http.StatusServiceUnavailable, "pouw trust registry is unavailable")
			return
		}

		status, err := app.PouwKeeper.GetEnterpriseAuditTrustRegistryStatus(ctx)
		if err != nil {
			writePouwAPIError(w, http.StatusInternalServerError, "failed to load pouw trust registry status: "+err.Error())
			return
		}

		registry, err := app.PouwKeeper.GetEnterpriseAuditTrustRegistry(ctx)
		if err != nil && !errors.Is(err, pouwkeeper.ErrEnterpriseAuditTrustRegistryNotConfigured) {
			writePouwAPIError(w, http.StatusInternalServerError, "failed to load pouw trust registry: "+err.Error())
			return
		}

		resp := pouwTrustRegistryResponse{
			Configured: status != nil && status.Configured,
			Status:     status,
		}
		if err == nil {
			resp.Registry = registry
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// PouwTrustRegistryHistoryHandler exposes governance history for trust-registry
// mutations through the PoUW operator surface.
func (app *AethelredApp) PouwTrustRegistryHistoryHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writePouwAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.auditServer == nil {
			writePouwAPIError(w, http.StatusServiceUnavailable, "pouw trust registry history is unavailable")
			return
		}

		resp, err := app.auditServer.GetEnterpriseTrustRegistryHistory(r.Context(), &audithttp.GetEnterpriseTrustRegistryHistoryRequest{
			Filter: parsePouwTrustRegistryHistoryFilter(r),
		})
		if err != nil {
			writePouwAPIError(w, http.StatusInternalServerError, "failed to load pouw trust registry history: "+err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// PouwTrustComplianceExportAnchorsHandler exposes normalized anchored-export
// audit records so operator tooling can inspect export provenance without
// unpacking raw audit details.
func (app *AethelredApp) PouwTrustComplianceExportAnchorsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writePouwAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.auditServer == nil {
			writePouwAPIError(w, http.StatusServiceUnavailable, "pouw trust compliance export anchors are unavailable")
			return
		}

		baseFilter := parsePouwTrustRegistryHistoryFilter(r)
		limit := baseFilter.Limit
		offset := baseFilter.Offset
		baseFilter.Limit = 0
		baseFilter.Offset = 0

		recordsResp, err := app.auditServer.GetTrustComplianceExportAnchors(r.Context(), &audithttp.GetTrustComplianceExportAnchorsRequest{
			Filter: baseFilter,
		})
		if err != nil {
			writePouwAPIError(w, http.StatusInternalServerError, "failed to load pouw trust compliance export anchors: "+err.Error())
			return
		}

		anchorFilter := &auditexport.PouwTrustComplianceExportAnchorFilter{
			Format:      strings.TrimSpace(r.URL.Query().Get("format")),
			Signer:      strings.TrimSpace(r.URL.Query().Get("signer")),
			PackageHash: strings.TrimSpace(r.URL.Query().Get("package_hash")),
			Limit:       limit,
			Offset:      offset,
		}
		if signed, ok, err := parsePouwOptionalBoolQuery(r, "signed"); err != nil {
			writePouwAPIError(w, http.StatusBadRequest, err.Error())
			return
		} else if ok {
			anchorFilter.Signed = &signed
		}

		anchors := auditexport.SummarizePouwTrustComplianceExportAnchors(recordsResp.Records)
		filteredAnchors, total := auditexport.FilterPouwTrustComplianceExportAnchors(anchors, anchorFilter)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(auditexport.PouwTrustComplianceExportAnchorsResponse{
			Anchors: filteredAnchors,
			Total:   total,
		})
	})
}

// PouwControlLedgerPackageAnchorsHandler exposes normalized governance anchor
// records for portable control-ledger packages through the public PoUW operator
// surface.
func (app *AethelredApp) PouwControlLedgerPackageAnchorsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writePouwAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.auditServer == nil {
			writePouwAPIError(w, http.StatusServiceUnavailable, "pouw control ledger package anchors are unavailable")
			return
		}

		baseFilter := parsePouwTrustRegistryHistoryFilter(r)
		limit := baseFilter.Limit
		offset := baseFilter.Offset
		baseFilter.Limit = 0
		baseFilter.Offset = 0

		recordsResp, err := app.auditServer.GetControlLedgerPackageAnchors(r.Context(), &audithttp.GetControlLedgerPackageAnchorsRequest{
			Filter: baseFilter,
		})
		if err != nil {
			writePouwAPIError(w, http.StatusInternalServerError, "failed to load pouw control ledger package anchors: "+err.Error())
			return
		}

		anchorFilter := &audithttp.PortableControlLedgerPackageAnchorFilter{
			PackageHash: strings.TrimSpace(r.URL.Query().Get("package_hash")),
			LedgerID:    strings.TrimSpace(r.URL.Query().Get("ledger_id")),
			Signer:      strings.TrimSpace(r.URL.Query().Get("signer")),
			Limit:       limit,
			Offset:      offset,
		}
		if signed, ok, err := parsePouwOptionalBoolQuery(r, "signed"); err != nil {
			writePouwAPIError(w, http.StatusBadRequest, err.Error())
			return
		} else if ok {
			anchorFilter.Signed = &signed
		}

		filteredAnchors, total := audithttp.FilterPortableControlLedgerPackageAnchors(recordsResp.Anchors, anchorFilter)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(audithttp.GetControlLedgerPackageAnchorsResponse{
			Anchors: filteredAnchors,
			Total:   total,
		})
	})
}

// PouwTrustComplianceExportHandler exposes an auditor-friendly view that
// bundles current PoUW module posture, current trust registry state, and the
// governance history that produced it.
func (app *AethelredApp) PouwTrustComplianceExportHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writePouwAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if app == nil || app.auditServer == nil {
			writePouwAPIError(w, http.StatusServiceUnavailable, "pouw trust compliance export is unavailable")
			return
		}

		ctx := safeAuditKeeperContext(app)
		if ctx == nil {
			writePouwAPIError(w, http.StatusServiceUnavailable, "pouw trust compliance export is unavailable")
			return
		}

		moduleStatus, err := app.PouwKeeper.GetModuleStatus(ctx)
		if err != nil {
			writePouwAPIError(w, http.StatusInternalServerError, "failed to load pouw module status: "+err.Error())
			return
		}

		trustStatus, err := app.PouwKeeper.GetEnterpriseAuditTrustRegistryStatus(ctx)
		if err != nil {
			writePouwAPIError(w, http.StatusInternalServerError, "failed to load pouw trust registry status: "+err.Error())
			return
		}

		registry, err := app.PouwKeeper.GetEnterpriseAuditTrustRegistry(ctx)
		if err != nil && !errors.Is(err, pouwkeeper.ErrEnterpriseAuditTrustRegistryNotConfigured) {
			writePouwAPIError(w, http.StatusInternalServerError, "failed to load pouw trust registry: "+err.Error())
			return
		}

		historyResp, err := app.auditServer.GetEnterpriseTrustRegistryHistory(r.Context(), &audithttp.GetEnterpriseTrustRegistryHistoryRequest{
			Filter: parsePouwTrustRegistryHistoryFilter(r),
		})
		if err != nil {
			writePouwAPIError(w, http.StatusInternalServerError, "failed to load pouw trust registry history: "+err.Error())
			return
		}

		generatedAt := time.Now().UTC().Format(time.RFC3339Nano)
		var complianceReport *pouwkeeper.ComplianceReport
		if sdkCtx, ok := ctx.(sdk.Context); ok {
			if !sdkCtx.BlockTime().IsZero() {
				generatedAt = sdkCtx.BlockTime().UTC().Format(time.RFC3339Nano)
			}
			complianceReport = pouwkeeper.GenerateComplianceReport(sdkCtx, app.PouwKeeper)
		}

		exportDoc := auditexport.BuildPouwTrustComplianceExport(
			generatedAt,
			moduleStatus,
			trustStatus,
			registry,
			historyResp.Records,
			complianceReport,
		)

		format, err := auditexport.NormalizePouwTrustComplianceFormat(r.URL.Query().Get("format"))
		if err != nil {
			writePouwAPIError(w, http.StatusBadRequest, err.Error())
			return
		}

		var (
			payload     []byte
			contentType string
			filename    string
		)
		switch format {
		case "json":
			payload, err = auditexport.ExportPouwTrustComplianceJSON(exportDoc)
			contentType = "application/json"
			filename = "pouw-trust-compliance-export.json"
		case "csv":
			payload, err = auditexport.ExportPouwTrustComplianceCSV(exportDoc)
			contentType = "text/csv; charset=utf-8"
			filename = "pouw-trust-compliance-export.csv"
		case "oscal":
			payload, err = auditexport.ExportPouwTrustComplianceOSCAL(exportDoc)
			contentType = "application/json"
			filename = "pouw-trust-compliance-export.oscal.json"
		}
		if err != nil {
			writePouwAPIError(w, http.StatusInternalServerError, "failed to export pouw trust compliance: "+err.Error())
			return
		}

		if parsePouwBoolQuery(r, "package") {
			exportPackage, err := auditexport.CreatePouwTrustCompliancePackage(exportDoc, format, payload)
			if err != nil {
				writePouwAPIError(w, http.StatusInternalServerError, "failed to package pouw trust compliance export: "+err.Error())
				return
			}
			if signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app); ok {
				if err := exportPackage.SignEd25519(privateKey, signer); err != nil {
					writePouwAPIError(w, http.StatusInternalServerError, "failed to sign pouw trust compliance package: "+err.Error())
					return
				}
			}
			if auditAnchor := anchorPouwTrustCompliancePackage(app, ctx, exportPackage); auditAnchor != nil {
				exportPackage.AuditAnchor = auditAnchor
			}
			payload, err = exportPackage.Marshal()
			if err != nil {
				writePouwAPIError(w, http.StatusInternalServerError, "failed to encode pouw trust compliance package: "+err.Error())
				return
			}
			contentType = "application/json"
			filename = "pouw-trust-compliance-export.package.json"
		}

		w.Header().Set("Content-Type", contentType)
		if filename != "" && (format != "json" || parsePouwBoolQuery(r, "package")) {
			w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
}

// PouwTrustCompliancePackageVerifyHandler verifies a posted packaged export and
// optionally correlates it with matching anchored export records from the
// running node.
func (app *AethelredApp) PouwTrustCompliancePackageVerifyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writePouwAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var pkg auditexport.PouwTrustCompliancePackage
		if err := json.NewDecoder(r.Body).Decode(&pkg); err != nil {
			writePouwAPIError(w, http.StatusBadRequest, "invalid pouw trust compliance package payload")
			return
		}

		resp := pouwTrustCompliancePackageVerifyResponse{
			Verification: auditexport.VerifyPouwTrustCompliancePackageDetailed(&pkg),
		}

		if app != nil && app.auditServer != nil && resp.Verification != nil && resp.Verification.Summary != nil {
			packageHash := strings.TrimSpace(resp.Verification.Summary.PackageHash)
			if packageHash != "" {
				rawAnchors, err := app.auditServer.GetTrustComplianceExportAnchors(r.Context(), &audithttp.GetTrustComplianceExportAnchorsRequest{
					Filter: audithttp.NewFilter().WithKeywords(packageHash),
				})
				if err == nil {
					anchors := auditexport.SummarizePouwTrustComplianceExportAnchors(rawAnchors.Records)
					resp.AnchorMatches, resp.AnchorMatchCount = auditexport.FilterPouwTrustComplianceExportAnchors(
						anchors,
						&auditexport.PouwTrustComplianceExportAnchorFilter{PackageHash: packageHash},
					)
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// PouwPortableControlLedgerPackageVerifyHandler verifies a posted portable
// control-ledger package and, when available, correlates it with matching
// governance anchor records from the running node.
func (app *AethelredApp) PouwPortableControlLedgerPackageVerifyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writePouwAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var pkg evidence.PortableControlLedgerPackage
		if err := json.NewDecoder(r.Body).Decode(&pkg); err != nil {
			writePouwAPIError(w, http.StatusBadRequest, "invalid portable control ledger package payload")
			return
		}

		resp := pouwPortableControlLedgerPackageVerifyResponse{
			Valid:       false,
			PackageHash: pkg.PackageHash,
		}
		if pkg.Ledger != nil && pkg.Ledger.Bundle != nil {
			resp.LedgerID = pkg.Ledger.Bundle.ID
			resp.Summary = &pkg.Ledger.Summary
		}

		if app != nil && app.auditServer != nil {
			verified, err := app.auditServer.VerifyPortableControlLedgerPackage(r.Context(), &audithttp.VerifyPortableControlLedgerPackageRequest{
				Package: &pkg,
			})
			if err != nil {
				writePouwAPIError(w, http.StatusInternalServerError, "failed to verify portable control ledger package: "+err.Error())
				return
			}
			resp = *verified
		} else if err := evidence.VerifyPortableControlLedgerPackage(&pkg); err != nil {
			resp.Error = err.Error()
		} else {
			resp.Valid = true
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

func writePouwAPIError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(pouwAPIErrorResponse{Error: msg})
}

func parsePouwTrustRegistryHistoryFilter(r *http.Request) *audithttp.Filter {
	filter := audithttp.NewFilter()
	if r == nil {
		return filter
	}

	query := r.URL.Query()
	if actor := strings.TrimSpace(query.Get("actor")); actor != "" {
		filter.WithActors(actor)
	}
	for _, keyword := range query["keyword"] {
		if keyword = strings.TrimSpace(keyword); keyword != "" {
			filter.Keywords = append(filter.Keywords, keyword)
		}
	}
	if keyword := strings.TrimSpace(query.Get("q")); keyword != "" {
		filter.Keywords = append(filter.Keywords, keyword)
	}
	if limit, err := strconv.Atoi(strings.TrimSpace(query.Get("limit"))); err == nil && limit > 0 {
		filter.Limit = limit
	}
	if offset, err := strconv.Atoi(strings.TrimSpace(query.Get("offset"))); err == nil && offset >= 0 {
		filter.Offset = offset
	}
	return filter
}

func parsePouwBoolQuery(r *http.Request, key string) bool {
	if r == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parsePouwOptionalBoolQuery(r *http.Request, key string) (bool, bool, error) {
	if r == nil {
		return false, false, nil
	}
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return false, false, nil
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true, true, nil
	case "0", "false", "no", "off":
		return false, true, nil
	default:
		return false, false, errors.New("invalid boolean query value for " + key)
	}
}

func resolvePouwTrustCompliancePackageSigner(app *AethelredApp) (string, ed25519.PrivateKey, bool) {
	if app == nil || !app.HasValidatorPrivateKey() {
		return "", nil, false
	}

	signer := ""
	if len(app.validatorConsAddr) > 0 {
		signer = hex.EncodeToString(app.validatorConsAddr)
	} else if derived, err := app.validatorConsensusAddress(); err == nil {
		signer = hex.EncodeToString(derived)
	}

	privateKey := ed25519.PrivateKey(make([]byte, len(app.validatorPrivKey)))
	copy(privateKey, app.validatorPrivKey)
	return signer, privateKey, true
}

func anchorPouwTrustCompliancePackage(app *AethelredApp, ctx context.Context, pkg *auditexport.PouwTrustCompliancePackage) *pouwkeeper.AuditRecord {
	if app == nil || pkg == nil {
		return nil
	}
	sdkCtx, ok := ctx.(sdk.Context)
	if !ok {
		return nil
	}
	logger := app.PouwKeeper.AuditLogger()
	if logger == nil {
		return nil
	}

	actor := "pouw_api"
	if pkg.Signature != nil && strings.TrimSpace(pkg.Signature.Signer) != "" {
		actor = pkg.Signature.Signer
	}
	details := map[string]string{
		"package_hash":    pkg.Manifest.PackageHash,
		"payload_hash":    pkg.Manifest.PayloadHash,
		"document_hash":   pkg.Manifest.DocumentHash,
		"format":          pkg.Manifest.Format,
		"export_version":  pkg.Manifest.ExportVersion,
		"generated_at":    pkg.Manifest.GeneratedAt,
		"history_count":   strconv.Itoa(pkg.Manifest.HistoryCount),
		"signed":          strconv.FormatBool(pkg.Signature != nil),
		"custody_entries": strconv.Itoa(len(pkg.ChainOfCustody)),
	}
	if strings.TrimSpace(pkg.Manifest.TrustRegistryVersion) != "" {
		details["trust_registry_version"] = pkg.Manifest.TrustRegistryVersion
	}
	if strings.TrimSpace(pkg.Manifest.TrustRegistrySource) != "" {
		details["trust_registry_source"] = pkg.Manifest.TrustRegistrySource
	}
	if pkg.Manifest.ComplianceTotal > 0 {
		details["compliance_total_controls"] = strconv.Itoa(pkg.Manifest.ComplianceTotal)
		details["compliance_mapped_controls"] = strconv.Itoa(pkg.Manifest.ComplianceMapped)
		details["compliance_gap_controls"] = strconv.Itoa(pkg.Manifest.ComplianceGap)
	}
	if pkg.Signature != nil {
		details["signer"] = pkg.Signature.Signer
		details["signature_key_id"] = pkg.Signature.KeyID
		details["signature_algorithm"] = pkg.Signature.Algorithm
		details["signed_at"] = pkg.Signature.SignedAt
	}

	record := logger.AuditTrustComplianceExport(sdkCtx, actor, details)
	if record == nil {
		return nil
	}
	cloned := *record
	cloned.Details = cloneAuditDetails(record.Details)
	return &cloned
}

func anchorPortableControlLedgerPackage(app *AethelredApp, pkg *evidence.PortableControlLedgerPackage) *evidence.PortableControlLedgerPackageAuditAnchor {
	if app == nil || pkg == nil {
		return nil
	}
	ctx := safeAuditKeeperContext(app)
	sdkCtx, ok := ctx.(sdk.Context)
	if !ok {
		return nil
	}
	logger := app.PouwKeeper.AuditLogger()
	if logger == nil {
		return nil
	}

	actor := "audit_api"
	if pkg.Signature != nil && strings.TrimSpace(pkg.Signature.Signer) != "" {
		actor = pkg.Signature.Signer
	}
	record := logger.AuditControlLedgerPackage(sdkCtx, actor, pkg.AnchorDetails())
	if record == nil {
		return nil
	}
	return &evidence.PortableControlLedgerPackageAuditAnchor{
		Sequence:     record.Sequence,
		RecordHash:   record.RecordHash,
		PreviousHash: record.PreviousHash,
		Category:     string(record.Category),
		Severity:     string(record.Severity),
		Action:       record.Action,
		BlockHeight:  record.BlockHeight,
		Timestamp:    record.Timestamp,
		Actor:        record.Actor,
		Details:      cloneAuditDetails(record.Details),
	}
}

func cloneAuditDetails(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
