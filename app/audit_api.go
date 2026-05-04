package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cosmos/cosmos-sdk/client/flags"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	"github.com/spf13/cast"

	"github.com/aethelred/aethelred/pkg/audit"
	"github.com/aethelred/aethelred/pkg/evidence"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

const (
	auditTrustBootstrapModeStartupFile   = "startup_file"
	auditTrustBootstrapReasonStartupFile = "bootstrap enterprise trust registry from configured file"
	auditTrustBootstrapActorStartupFile  = "audit_startup_bootstrap"
)

func (app *AethelredApp) initAuditInfrastructure(appOpts servertypes.AppOptions) {
	auditSource := app.PouwKeeper.AuditLogger()
	if auditSource == nil {
		app.Logger().Warn("Audit API not initialized because the PoUW audit source is unavailable")
		return
	}

	studio, err := audit.NewStudio(audit.Config{
		LogSource:       auditSource,
		ExportFormats:   []string{"json", "csv", "oscal"},
		RetentionPolicy: nil,
	})
	if err != nil {
		app.Logger().Error("Audit API initialization failed while building the audit studio", "error", err)
		return
	}

	controlLedgerDir := resolveAuditControlLedgerDir(appOpts)
	server, err := audit.NewPersistentAuditServer(studio, nil, controlLedgerDir)
	if err != nil {
		app.Logger().Error("Audit API initialization failed while creating the persistent audit server",
			"error", err,
			"control_ledger_dir", controlLedgerDir,
		)
		return
	}

	bootstrapSource, bootstrapStatus := bootstrapKeeperEnterpriseAuditTrustFromFile(app, appOpts)
	writeAuthorizer, writeAuthMode, writeAuthMessage := resolveAuditControlLedgerWriteAuthorizer(app, appOpts)
	server.SetControlLedgerWriteAuthorizer(writeAuthorizer)
	server.SetPortableControlLedgerPackageSigner(resolveAuditPortableControlLedgerPackageSigner(app))
	server.SetPortableControlLedgerPackageAnchorer(resolveAuditPortableControlLedgerPackageAnchorer(app))
	trustRegistryService, trustRegistryServiceMessage := resolveAuditEnterpriseTrustRegistryService(app)
	server.SetEnterpriseTrustRegistryService(trustRegistryService)
	trustRegistryAdminAuthorizer, trustRegistryAdminMode, trustRegistryAdminMessage := resolveAuditTrustRegistryAdminAuthorizer(appOpts)
	server.SetTrustRegistryAdminAuthorizer(trustRegistryAdminAuthorizer)

	app.auditStudio = studio
	app.auditServer = server
	app.auditControlLedgerDir = controlLedgerDir
	app.Logger().Info("Audit API initialized",
		"control_ledger_dir", controlLedgerDir,
		"export_formats", "json,csv,oscal",
		"trust_registry_bootstrap_source", bootstrapSource,
		"trust_registry_bootstrap_status", bootstrapStatus,
		"write_auth_mode", writeAuthMode,
		"write_auth_message", writeAuthMessage,
		"trust_registry_service", trustRegistryServiceMessage,
		"trust_registry_admin_mode", trustRegistryAdminMode,
		"trust_registry_admin_message", trustRegistryAdminMessage,
	)
}

func resolveAuditControlLedgerDir(appOpts servertypes.AppOptions) string {
	configuredDir := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.audit.control_ledger_dir")),
		cast.ToString(appOpts.Get("audit.control_ledger_dir")),
		os.Getenv("AETHELRED_AUDIT_CONTROL_LEDGER_DIR"),
	)
	if configuredDir != "" {
		return filepath.Clean(configuredDir)
	}

	homePath := cast.ToString(appOpts.Get(flags.FlagHome))
	if homePath == "" {
		homePath = DefaultNodeHome
	}
	if homePath == "" {
		return filepath.Clean(filepath.Join(".", "data", "audit", "control-ledgers"))
	}

	return filepath.Join(homePath, "data", "audit", "control-ledgers")
}

func resolveAuditPortableControlLedgerPackageSigner(app *AethelredApp) audit.PortableControlLedgerPackageSigner {
	if app == nil {
		return nil
	}
	return func(_ context.Context, pkg *evidence.PortableControlLedgerPackage) error {
		signer, privateKey, ok := resolvePouwTrustCompliancePackageSigner(app)
		if !ok {
			return fmt.Errorf("audit/api: %w: validator private key not configured", audit.ErrWriteDisabled)
		}
		return pkg.SignEd25519(privateKey, signer)
	}
}

func resolveAuditPortableControlLedgerPackageAnchorer(app *AethelredApp) audit.PortableControlLedgerPackageAnchorer {
	if app == nil {
		return nil
	}
	return func(_ context.Context, pkg *evidence.PortableControlLedgerPackage) error {
		anchor := anchorPortableControlLedgerPackage(app, pkg)
		if anchor == nil {
			return fmt.Errorf("audit/api: %w: portable control-ledger package anchor is unavailable", audit.ErrWriteDisabled)
		}
		pkg.AuditAnchor = anchor
		return nil
	}
}

func (app *AethelredApp) retryAuditBootstrapAfterStateReady(appOpts servertypes.AppOptions) {
	if app == nil {
		return
	}
	registryPath := resolveAuditEnterpriseTrustRegistryPath(appOpts)
	if registryPath == "" {
		return
	}

	bootstrapSource, bootstrapStatus := bootstrapKeeperEnterpriseAuditTrustFromFile(app, appOpts)
	switch {
	case strings.HasPrefix(bootstrapStatus, "bootstrapped"):
		app.Logger().Info("Audit trust-registry bootstrap completed after state initialization",
			"trust_registry_bootstrap_source", bootstrapSource,
			"trust_registry_bootstrap_status", bootstrapStatus,
		)
	case strings.HasPrefix(bootstrapStatus, "failed:"):
		app.Logger().Error("Audit trust-registry bootstrap retry failed after state initialization",
			"trust_registry_bootstrap_source", bootstrapSource,
			"trust_registry_bootstrap_status", bootstrapStatus,
		)
	}
}

func resolveAuditControlLedgerWriteAuthorizer(app *AethelredApp, appOpts servertypes.AppOptions) (audit.ControlLedgerWriteAuthorizer, string, string) {
	if allowUnauthenticatedAuditWrites(appOpts) {
		return nil, "unauthenticated", "control-ledger writes are enabled without authentication"
	}

	strategies := make([]audit.ControlLedgerWriteAuthorizer, 0, 2)
	authModes := make([]string, 0, 2)
	authMessages := make([]string, 0, 2)

	if enterpriseAuthorizer, authMode, authMessage, err := resolveAuditEnterpriseWriteAuthorizer(app, appOpts); err != nil {
		return audit.NewDisabledWriteAuthorizer("invalid enterprise policy-receipt authorization configuration"), "disabled", err.Error()
	} else if enterpriseAuthorizer != nil {
		strategies = append(strategies, enterpriseAuthorizer)
		authModes = append(authModes, authMode)
		authMessages = append(authMessages, authMessage)
	}

	writeToken := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.audit.api.write_token")),
		cast.ToString(appOpts.Get("audit.api.write_token")),
		os.Getenv("AETHELRED_AUDIT_API_WRITE_TOKEN"),
	)
	if writeToken != "" {
		authorizer, err := audit.NewStaticBearerTokenAuthorizer(writeToken)
		if err != nil {
			return audit.NewDisabledWriteAuthorizer("invalid write-token configuration"), "disabled", err.Error()
		}
		strategies = append(strategies, authorizer)
		authModes = append(authModes, "bearer_token")
		authMessages = append(authMessages, "control-ledger writes accept Authorization: Bearer <token>")
	}

	switch len(strategies) {
	case 0:
		return audit.NewDisabledWriteAuthorizer("configure audit write auth to enable mutating control-ledger APIs"), "disabled", "control-ledger writes are disabled until a bearer token, keeper-backed enterprise trust, enterprise trust registry, or enterprise signer configuration is configured"
	case 1:
		return strategies[0], authModes[0], authMessages[0]
	default:
		return audit.NewAnyOfControlLedgerWriteAuthorizer(strategies...), strings.Join(authModes, "+"), strings.Join(authMessages, "; ")
	}
}

func bootstrapKeeperEnterpriseAuditTrustFromFile(app *AethelredApp, appOpts servertypes.AppOptions) (string, string) {
	if app == nil {
		return "", "skipped: app is unavailable"
	}
	registryPath := resolveAuditEnterpriseTrustRegistryPath(appOpts)
	if registryPath == "" {
		return "", "skipped: no bootstrap trust registry path configured"
	}

	ctx := safeAuditKeeperContext(app)
	if ctx == nil {
		return registryPath, "skipped: keeper context is unavailable during startup"
	}

	if _, err := app.PouwKeeper.GetEnterpriseAuditTrustRegistry(ctx); err == nil {
		return registryPath, "skipped: keeper-backed trust registry already configured"
	} else if !errors.Is(err, pouwkeeper.ErrEnterpriseAuditTrustRegistryNotConfigured) {
		app.Logger().Error("Audit trust-registry bootstrap failed while checking keeper state", "error", err, "path", registryPath)
		return registryPath, "failed: " + err.Error()
	}

	data, err := os.ReadFile(registryPath)
	if err != nil {
		app.Logger().Error("Audit trust-registry bootstrap failed while reading registry file", "error", err, "path", registryPath)
		return registryPath, "failed: " + err.Error()
	}

	var registry pouwkeeper.EnterpriseAuditTrustRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		app.Logger().Error("Audit trust-registry bootstrap failed while decoding registry file", "error", err, "path", registryPath)
		return registryPath, "failed: " + err.Error()
	}

	if _, err := audit.PromoteEnterpriseAuditTrustRegistryToGovernedKeeper(
		&app.PouwKeeper,
		ctx,
		&registry,
		auditTrustBootstrapModeStartupFile,
		auditTrustBootstrapReasonStartupFile,
		auditTrustBootstrapActorStartupFile,
	); err != nil {
		app.Logger().Error("Audit trust-registry bootstrap failed while promoting governed keeper state", "error", err, "path", registryPath)
		return registryPath, "failed: " + err.Error()
	}

	app.Logger().Info("Bootstrapped keeper-backed enterprise audit trust registry from registry file via governed keeper state", "path", registryPath)
	return registryPath, "bootstrapped into governed keeper state"
}

func resolveAuditEnterpriseWriteAuthorizer(app *AethelredApp, appOpts servertypes.AppOptions) (audit.ControlLedgerWriteAuthorizer, string, string, error) {
	var fallbackSource audit.EnterpriseControlLedgerTrustSource
	authModes := make([]string, 0, 3)
	authMessages := make([]string, 0, 3)

	if trustRegistryPath := resolveAuditEnterpriseTrustRegistryPath(appOpts); trustRegistryPath != "" {
		trustSource, err := audit.NewFileEnterpriseControlLedgerTrustSource(trustRegistryPath)
		if err != nil {
			return nil, "", "", err
		}
		if _, err := trustSource.Snapshot(context.Background()); err != nil {
			return nil, "", "", err
		}
		fallbackSource = trustSource
		authModes = append(authModes, "trust_registry_file")
		authMessages = append(authMessages, "bootstrap trust registry: "+trustRegistryPath)
	} else {
		staticSource, hasStaticConfig, err := resolveAuditEnterpriseStaticTrustSource(appOpts)
		if err != nil {
			return nil, "", "", err
		}
		if hasStaticConfig {
			fallbackSource = staticSource
			authModes = append(authModes, "startup_config")
			authMessages = append(authMessages, "bootstrap trust from configured signer and sponsor allowlists")
		}
	}

	hasKeeperRegistry, err := hasKeeperBackedEnterpriseAuditTrust(app)
	if err != nil {
		return nil, "", "", err
	}
	trustRegistryAdminTokenConfigured := auditTrustRegistryAdminToken(appOpts) != ""
	if app == nil && !hasKeeperRegistry && fallbackSource == nil {
		return nil, "", "", nil
	}
	if app != nil && !hasKeeperRegistry && fallbackSource == nil && !trustRegistryAdminTokenConfigured {
		return nil, "", "", nil
	}

	trustSource := fallbackSource
	if app != nil {
		keeperSource, err := audit.NewPouwKeeperEnterpriseControlLedgerTrustSource(
			&app.PouwKeeper,
			func() context.Context { return safeAuditKeeperContext(app) },
			fallbackSource,
		)
		if err != nil {
			return nil, "", "", err
		}
		trustSource = keeperSource
		if hasKeeperRegistry {
			authModes = append([]string{"pouw_keeper"}, authModes...)
			authMessages = append([]string{"keeper-backed enterprise trust is the active source of truth"}, authMessages...)
		} else if fallbackSource == nil {
			authModes = append([]string{"pouw_keeper_waiting"}, authModes...)
			authMessages = append([]string{"keeper-backed enterprise trust is provisionable live and will activate once the registry is populated"}, authMessages...)
		} else if fallbackSource != nil {
			authModes = append([]string{"pouw_keeper_preferred"}, authModes...)
			authMessages = append([]string{"keeper-backed enterprise trust will override bootstrap trust once populated"}, authMessages...)
		}
	}

	enterpriseAuthorizer, err := audit.NewEnterpriseControlLedgerWriteAuthorizer(audit.EnterpriseControlLedgerWriteConfig{
		TrustSource: trustSource,
	})
	if err != nil {
		return nil, "", "", err
	}

	mode := "enterprise_policy_receipt"
	if len(authModes) > 0 {
		mode += "+" + strings.Join(authModes, "+")
	}
	message := "control-ledger writes require enterprise_auth claims validated against the active enterprise trust source"
	if len(authMessages) > 0 {
		message += "; " + strings.Join(authMessages, "; ")
	}
	return enterpriseAuthorizer, mode, message, nil
}

func resolveAuditEnterpriseTrustRegistryService(app *AethelredApp) (audit.EnterpriseTrustRegistryService, string) {
	if app == nil {
		return nil, "disabled: app is unavailable"
	}
	service, err := audit.NewPouwKeeperEnterpriseTrustRegistryService(
		&app.PouwKeeper,
		func() context.Context { return safeAuditKeeperContext(app) },
		func() *pouwkeeper.AuditLogger { return app.PouwKeeper.AuditLogger() },
	)
	if err != nil {
		app.Logger().Error("Audit trust-registry service initialization failed", "error", err)
		return nil, "disabled: " + err.Error()
	}
	return service, "keeper-backed enterprise trust registry management enabled"
}

func resolveAuditTrustRegistryAdminAuthorizer(appOpts servertypes.AppOptions) (audit.RequestAuthorizer, string, string) {
	adminToken := auditTrustRegistryAdminToken(appOpts)
	if adminToken == "" {
		return audit.NewDisabledRequestAuthorizer("configure a dedicated trust-registry admin token to enable registry mutations"), "disabled", "trust-registry mutations are disabled until a dedicated admin token is configured"
	}

	authorizer, err := audit.NewStaticBearerTokenRequestAuthorizer(adminToken)
	if err != nil {
		return audit.NewDisabledRequestAuthorizer("invalid trust-registry admin token configuration"), "disabled", err.Error()
	}
	return authorizer, "bearer_token", "trust-registry mutations require Authorization: Bearer <admin-token>"
}

func auditTrustRegistryAdminToken(appOpts servertypes.AppOptions) string {
	return firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.audit.api.trust_registry_admin_token")),
		cast.ToString(appOpts.Get("audit.api.trust_registry_admin_token")),
		os.Getenv("AETHELRED_AUDIT_TRUST_REGISTRY_ADMIN_TOKEN"),
	)
}

func resolveAuditEnterpriseStaticTrustSource(appOpts servertypes.AppOptions) (audit.EnterpriseControlLedgerTrustSource, bool, error) {
	trustedPolicySignersConfig := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.audit.api.enterprise_policy_signers")),
		cast.ToString(appOpts.Get("audit.api.enterprise_policy_signers")),
		os.Getenv("AETHELRED_AUDIT_ENTERPRISE_POLICY_SIGNERS"),
	)
	if trustedPolicySignersConfig == "" {
		return nil, false, nil
	}

	trustedPolicySigners, err := parseAuditPolicySignerConfig(trustedPolicySignersConfig)
	if err != nil {
		return nil, false, err
	}

	trustSource, err := audit.NewEnterpriseControlLedgerTrustSourceFromConfig(audit.EnterpriseControlLedgerWriteConfig{
		TrustedPolicySigners: trustedPolicySigners,
		RequiredAction: firstNonEmpty(
			cast.ToString(appOpts.Get("aethelred.audit.api.enterprise_required_action")),
			cast.ToString(appOpts.Get("audit.api.enterprise_required_action")),
			os.Getenv("AETHELRED_AUDIT_ENTERPRISE_REQUIRED_ACTION"),
		),
		RequiredJurisdiction: firstNonEmpty(
			cast.ToString(appOpts.Get("aethelred.audit.api.enterprise_required_jurisdiction")),
			cast.ToString(appOpts.Get("audit.api.enterprise_required_jurisdiction")),
			os.Getenv("AETHELRED_AUDIT_ENTERPRISE_REQUIRED_JURISDICTION"),
		),
		AllowedSponsors: parseAuditCSVList(firstNonEmpty(
			cast.ToString(appOpts.Get("aethelred.audit.api.enterprise_allowed_sponsors")),
			cast.ToString(appOpts.Get("audit.api.enterprise_allowed_sponsors")),
			os.Getenv("AETHELRED_AUDIT_ENTERPRISE_ALLOWED_SPONSORS"),
		)),
	})
	if err != nil {
		return nil, false, err
	}
	return trustSource, true, nil
}

func resolveAuditEnterpriseTrustRegistryPath(appOpts servertypes.AppOptions) string {
	configuredPath := firstNonEmpty(
		cast.ToString(appOpts.Get("aethelred.audit.api.enterprise_trust_registry_path")),
		cast.ToString(appOpts.Get("audit.api.enterprise_trust_registry_path")),
		os.Getenv("AETHELRED_AUDIT_ENTERPRISE_TRUST_REGISTRY_PATH"),
	)
	if configuredPath != "" {
		return filepath.Clean(configuredPath)
	}

	homePath := cast.ToString(appOpts.Get(flags.FlagHome))
	if homePath == "" {
		homePath = DefaultNodeHome
	}
	if homePath == "" {
		return ""
	}

	defaultPath := filepath.Join(homePath, "config", "audit-enterprise-trust.json")
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath
	}
	return ""
}

func allowUnauthenticatedAuditWrites(appOpts servertypes.AppOptions) bool {
	if cast.ToBool(appOpts.Get("aethelred.audit.api.allow_unauthenticated_writes")) {
		return true
	}
	if cast.ToBool(appOpts.Get("audit.api.allow_unauthenticated_writes")) {
		return true
	}
	return cast.ToBool(os.Getenv("AETHELRED_AUDIT_ALLOW_UNAUTHENTICATED_WRITES"))
}

func parseAuditPolicySignerConfig(raw string) (map[string]string, error) {
	entries := parseAuditCSVList(raw)
	if len(entries) == 0 {
		return nil, nil
	}

	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			return nil, os.ErrInvalid
		}
		signerDID := strings.TrimSpace(parts[0])
		publicKeyHex := strings.TrimSpace(parts[1])
		if signerDID == "" || publicKeyHex == "" {
			return nil, os.ErrInvalid
		}
		out[signerDID] = publicKeyHex
	}
	return out, nil
}

func parseAuditCSVList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized := strings.TrimSpace(part)
		if normalized != "" {
			out = append(out, normalized)
		}
	}
	return out
}

func hasKeeperBackedEnterpriseAuditTrust(app *AethelredApp) (bool, error) {
	if app == nil {
		return false, nil
	}
	ctx := safeAuditKeeperContext(app)
	if ctx == nil {
		return false, nil
	}
	_, err := app.PouwKeeper.GetEnterpriseAuditTrustRegistry(ctx)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, pouwkeeper.ErrEnterpriseAuditTrustRegistryNotConfigured) {
		return false, nil
	}
	return false, err
}

func safeAuditKeeperContext(app *AethelredApp) (ctx context.Context) {
	if app == nil || app.BaseApp == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			ctx = nil
		}
	}()
	return app.NewContext(true)
}
