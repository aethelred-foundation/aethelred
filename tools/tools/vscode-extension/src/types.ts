/**
 * Aethelred VS Code Extension - Core Types
 *
 * Enterprise-grade type definitions for the Sovereign Copilot.
 * These types mirror the Rust CLI output and provide strong typing
 * throughout the extension.
 */

import * as vscode from 'vscode';

// =============================================================================
// Jurisdiction Types
// =============================================================================

/**
 * Supported legal jurisdictions for compliance checking.
 */
export type Jurisdiction =
    | 'Global'
    | 'UAE'
    | 'UAE-ADGM'
    | 'UAE-DIFC'
    | 'Saudi-Arabia'
    | 'EU'
    | 'EU-Germany'
    | 'EU-France'
    | 'UK'
    | 'US'
    | 'US-California'
    | 'US-NewYork'
    | 'Singapore'
    | 'China'
    | 'Japan'
    | 'Australia'
    | 'India'
    | 'Brazil'
    | 'Canada';

/**
 * Jurisdiction metadata with regulatory details.
 */
export interface JurisdictionInfo {
    code: Jurisdiction;
    name: string;
    flag: string;
    regulations: Regulation[];
    requiresDataLocalization: boolean;
    requiresTee: boolean;
    adequacyDecisions: Jurisdiction[];
}

// =============================================================================
// Regulation Types
// =============================================================================

/**
 * Supported compliance regulations.
 */
export type Regulation =
    | 'GDPR'
    | 'HIPAA'
    | 'CCPA'
    | 'UAE-DPL'
    | 'PIPL'
    | 'PDPA'
    | 'UK-GDPR'
    | 'PDPL-SA'
    | 'PCI-DSS'
    | 'SOX'
    | 'GLBA'
    | 'EU-AI-Act'
    | 'HITECH'
    | 'APPI'
    | 'PIPA'
    | 'LGPD'
    | 'DPDP'
    | 'PIPEDA';

/**
 * Regulation metadata with legal references.
 */
export interface RegulationInfo {
    code: Regulation;
    name: string;
    fullName: string;
    jurisdiction: Jurisdiction;
    effectiveDate: string;
    documentationUrl: string;
    articles: ArticleReference[];
}

/**
 * Reference to a specific legal article.
 */
export interface ArticleReference {
    article: string;
    title: string;
    summary: string;
    url: string;
}

// =============================================================================
// Violation Types
// =============================================================================

/**
 * Severity levels for compliance violations.
 */
export type ViolationSeverity = 'critical' | 'error' | 'warning' | 'info' | 'hint';

/**
 * Categories of compliance violations.
 */
export type ViolationCategory =
    | 'data-sovereignty'
    | 'cross-border-transfer'
    | 'consent'
    | 'retention'
    | 'encryption'
    | 'access-control'
    | 'audit-logging'
    | 'data-minimization'
    | 'purpose-limitation'
    | 'tee-requirement'
    | 'hardware-attestation'
    | 'ai-transparency'
    | 'model-governance';

/**
 * A single compliance violation detected in code.
 */
export interface ComplianceViolation {
    /** Unique violation identifier */
    id: string;

    /** Human-readable message */
    message: string;

    /** Detailed explanation */
    description: string;

    /** Severity level */
    severity: ViolationSeverity;

    /** Violation category */
    category: ViolationCategory;

    /** Violated regulation */
    regulation: Regulation;

    /** Specific legal article reference */
    legalReference?: ArticleReference;

    /** Source file path */
    file: string;

    /** Line number (1-indexed) */
    line: number;

    /** Column number (1-indexed) */
    column: number;

    /** End line (for multi-line violations) */
    endLine?: number;

    /** End column */
    endColumn?: number;

    /** The violating code snippet */
    codeSnippet?: string;

    /** Suggested fix */
    fix?: ViolationFix;

    /** Additional fixes */
    additionalFixes?: ViolationFix[];

    /** Related violations */
    relatedViolations?: string[];

    /** Timestamp when detected */
    detectedAt: string;

    /** Hash of the violation for deduplication */
    hash: string;
}

/**
 * A suggested fix for a violation.
 */
export interface ViolationFix {
    /** Fix title */
    title: string;

    /** Description of what the fix does */
    description: string;

    /** The replacement code */
    replacement?: string;

    /** Whether this fix is preferred/recommended */
    isPreferred: boolean;

    /** Edit operations to apply */
    edits?: TextEdit[];

    /** Commands to run after applying fix */
    commands?: FixCommand[];
}

/**
 * A text edit operation.
 */
export interface TextEdit {
    range: {
        start: { line: number; column: number };
        end: { line: number; column: number };
    };
    newText: string;
}

/**
 * A command to run as part of a fix.
 */
export interface FixCommand {
    command: string;
    args?: unknown[];
    title: string;
}

// =============================================================================
// Compliance Report Types
// =============================================================================

/**
 * Complete compliance report from the CLI.
 */
export interface ComplianceReport {
    /** Report version */
    version: string;

    /** Timestamp of the scan */
    timestamp: string;

    /** Duration of the scan in milliseconds */
    durationMs: number;

    /** Target jurisdiction */
    jurisdiction: Jurisdiction;

    /** Active regulations */
    regulations: Regulation[];

    /** Files scanned */
    filesScanned: number;

    /** Lines of code analyzed */
    linesAnalyzed: number;

    /** Summary statistics */
    summary: ComplianceSummary;

    /** All violations */
    violations: ComplianceViolation[];

    /** Compliance score (0-100) */
    score: number;

    /** Risk level */
    riskLevel: 'low' | 'medium' | 'high' | 'critical';

    /** Recommendations */
    recommendations: Recommendation[];

    /** Metadata */
    metadata: ReportMetadata;
}

/**
 * Summary statistics for a compliance report.
 */
export interface ComplianceSummary {
    total: number;
    critical: number;
    error: number;
    warning: number;
    info: number;
    hint: number;
    fixed: number;
    suppressed: number;
}

/**
 * A compliance recommendation.
 */
export interface Recommendation {
    id: string;
    priority: 'high' | 'medium' | 'low';
    title: string;
    description: string;
    impact: string;
    effort: 'low' | 'medium' | 'high';
    category: ViolationCategory;
}

/**
 * Report metadata.
 */
export interface ReportMetadata {
    cliVersion: string;
    projectRoot: string;
    configPath?: string;
    gitCommit?: string;
    gitBranch?: string;
}

// =============================================================================
// Hardware Types
// =============================================================================

/**
 * Supported hardware types for TEE execution.
 */
export type HardwareType =
    | 'generic'
    | 'intel-sgx'
    | 'intel-sgx-dcap'
    | 'intel-tdx'
    | 'amd-sev'
    | 'amd-sev-snp'
    | 'arm-trustzone'
    | 'arm-cca'
    | 'aws-nitro'
    | 'azure-confidential'
    | 'gcp-confidential'
    | 'nvidia-h100'
    | 'nvidia-a100';

/**
 * Hardware capabilities and status.
 */
export interface HardwareInfo {
    type: HardwareType;
    name: string;
    available: boolean;
    securityLevel: number;
    supportsAttestation: boolean;
    features: string[];
    driver?: string;
    driverVersion?: string;
}

/**
 * Cost estimate for executing on hardware.
 */
export interface CostEstimate {
    /** Estimated cost in AETHEL tokens */
    costAethel: number;

    /** Power consumption in watts */
    powerWatts: number;

    /** Estimated execution time in milliseconds */
    executionTimeMs: number;

    /** Memory required in MB */
    memoryMb: number;

    /** TEE overhead percentage */
    teeOverheadPercent: number;

    /** Target hardware */
    hardware: HardwareType;

    /** Model complexity tier */
    complexityTier: 'simple' | 'moderate' | 'complex' | 'extreme';
}

// =============================================================================
// Seal Types
// =============================================================================

/**
 * Digital seal status.
 */
export type SealStatus = 'pending' | 'verified' | 'expired' | 'revoked' | 'invalid';

/**
 * A digital seal for verified computation.
 */
export interface DigitalSeal {
    id: string;
    modelCommitment: string;
    inputCommitment: string;
    outputCommitment: string;
    timestamp: string;
    blockHeight: number;
    validators: string[];
    status: SealStatus;
    jurisdiction: Jurisdiction;
    regulations: Regulation[];
    expiresAt?: string;
    transactionHash?: string;
}

// =============================================================================
// Configuration Types
// =============================================================================

/**
 * Extension configuration.
 */
export interface AethelredConfig {
    jurisdiction: Jurisdiction;
    regulations: Regulation[];
    linting: LintingConfig;
    cli: CliConfig;
    hardware: HardwareConfig;
    network: NetworkConfig;
    ui: UiConfig;
    logging: LoggingConfig;
}

export interface LintingConfig {
    enabled: boolean;
    onSave: boolean;
    onType: boolean;
    debounceMs: number;
    severity: ViolationSeverity;
}

export interface CliConfig {
    path: string;
    timeout: number;
}

export interface HardwareConfig {
    target: HardwareType | 'auto';
    simulatorEnabled: boolean;
}

export interface NetworkConfig {
    endpoint: string;
    chain: 'mainnet' | 'testnet' | 'devnet' | 'local';
}

export interface UiConfig {
    showStatusBar: boolean;
    showInlineHints: boolean;
    showCodeLens: boolean;
}

export interface LoggingConfig {
    level: 'error' | 'warn' | 'info' | 'debug' | 'trace';
}

// =============================================================================
// CLI Types
// =============================================================================

/**
 * CLI execution result.
 */
export interface CliResult<T> {
    success: boolean;
    data?: T;
    error?: CliError;
    stdout: string;
    stderr: string;
    exitCode: number;
    durationMs: number;
}

/**
 * CLI error information.
 */
export interface CliError {
    code: string;
    message: string;
    details?: string;
    suggestion?: string;
}

/**
 * CLI command options.
 */
export interface CliOptions {
    cwd?: string;
    timeout?: number;
    env?: Record<string, string>;
    cancellation?: vscode.CancellationToken;
}

// =============================================================================
// Event Types
// =============================================================================

/**
 * Compliance check event.
 */
export interface ComplianceCheckEvent {
    type: 'started' | 'progress' | 'completed' | 'error';
    timestamp: string;
    file?: string;
    progress?: number;
    report?: ComplianceReport;
    error?: Error;
}

/**
 * Violation change event.
 */
export interface ViolationChangeEvent {
    type: 'added' | 'removed' | 'updated';
    violations: ComplianceViolation[];
    file: string;
}

// =============================================================================
// Diagnostic Types
// =============================================================================

/**
 * Extended diagnostic with Aethelred metadata.
 */
export interface AethelredDiagnostic extends vscode.Diagnostic {
    violation?: ComplianceViolation;
    fixes?: ViolationFix[];
}

// =============================================================================
// View Types
// =============================================================================

/**
 * Tree item for the compliance explorer.
 */
export interface ComplianceTreeItem {
    id: string;
    label: string;
    description?: string;
    tooltip?: string;
    iconPath?: vscode.ThemeIcon | vscode.Uri;
    contextValue?: string;
    command?: vscode.Command;
    children?: ComplianceTreeItem[];
    collapsibleState?: vscode.TreeItemCollapsibleState;
}

// =============================================================================
// Sovereign Function Types
// =============================================================================

/**
 * Information about a sovereign function in code.
 */
export interface SovereignFunctionInfo {
    name: string;
    file: string;
    line: number;
    column: number;
    endLine: number;
    endColumn: number;
    decoratorLine: number;
    hardware?: HardwareType;
    jurisdiction?: Jurisdiction;
    compliance?: Regulation[];
    parameters?: SovereignParameter[];
    costEstimate?: CostEstimate;
}

/**
 * Parameter for a sovereign function.
 */
export interface SovereignParameter {
    name: string;
    type: string;
    isSovereign: boolean;
    classification?: 'public' | 'internal' | 'confidential' | 'sensitive' | 'restricted';
}

// =============================================================================
// Status Types
// =============================================================================

/**
 * Extension status.
 */
export interface ExtensionStatus {
    state: 'active' | 'inactive' | 'error' | 'loading';
    cliAvailable: boolean;
    cliVersion?: string;
    networkConnected: boolean;
    jurisdiction: Jurisdiction;
    violations: ComplianceSummary;
    lastCheck?: string;
    teeSimulatorRunning: boolean;
}

// =============================================================================
// Utility Types
// =============================================================================

/**
 * Disposable resource.
 */
export interface Disposable {
    dispose(): void;
}

/**
 * Event emitter interface.
 */
export interface EventEmitter<T> {
    event: vscode.Event<T>;
    fire(data: T): void;
    dispose(): void;
}
