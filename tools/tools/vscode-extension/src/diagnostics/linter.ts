/**
 * Aethelred VS Code Extension - Compliance Linter
 *
 * Enterprise-grade compliance linting with real-time diagnostics,
 * quick fixes, and code actions. This is the "red squiggly" logic
 * that highlights regulatory violations as developers type.
 */

import * as vscode from 'vscode';
import {
    ComplianceViolation,
    ComplianceReport,
    ViolationSeverity,
    ViolationFix,
    AethelredDiagnostic,
    Jurisdiction,
    Regulation,
} from '../types';
import { aethelCli } from '../services/cli';
import { configManager } from '../utils/config';
import { logger, CategoryLogger } from '../utils/logger';

/**
 * Debounce function for limiting lint frequency.
 */
function debounce<T extends (...args: unknown[]) => void>(
    fn: T,
    delay: number
): (...args: Parameters<T>) => void {
    let timeoutId: NodeJS.Timeout | null = null;

    return (...args: Parameters<T>) => {
        if (timeoutId) {
            clearTimeout(timeoutId);
        }
        timeoutId = setTimeout(() => {
            fn(...args);
            timeoutId = null;
        }, delay);
    };
}

/**
 * Linting statistics.
 */
export interface LintStats {
    totalLints: number;
    totalViolations: number;
    averageDurationMs: number;
    lastLintTime: Date | null;
}

/**
 * Enterprise-grade compliance linter for the Aethelred extension.
 */
export class ComplianceLinter {
    private readonly log: CategoryLogger;
    private readonly diagnosticCollection: vscode.DiagnosticCollection;
    private readonly violationMap = new Map<string, ComplianceViolation[]>();
    private readonly pendingLints = new Map<string, vscode.CancellationTokenSource>();
    private readonly stats: LintStats = {
        totalLints: 0,
        totalViolations: 0,
        averageDurationMs: 0,
        lastLintTime: null,
    };

    // Event emitters
    private readonly onDidUpdateViolationsEmitter = new vscode.EventEmitter<string>();
    private readonly onDidStartLintEmitter = new vscode.EventEmitter<vscode.TextDocument>();
    private readonly onDidEndLintEmitter = new vscode.EventEmitter<{ document: vscode.TextDocument; report?: ComplianceReport }>();

    // Debounced lint function
    private readonly debouncedLint: (document: vscode.TextDocument) => void;

    // Disposables
    private readonly disposables: vscode.Disposable[] = [];

    /**
     * Event fired when violations are updated.
     */
    readonly onDidUpdateViolations = this.onDidUpdateViolationsEmitter.event;

    /**
     * Event fired when linting starts.
     */
    readonly onDidStartLint = this.onDidStartLintEmitter.event;

    /**
     * Event fired when linting ends.
     */
    readonly onDidEndLint = this.onDidEndLintEmitter.event;

    constructor(context: vscode.ExtensionContext) {
        this.log = logger.createChild('Linter');

        // Create diagnostic collection
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('aethelred');
        context.subscriptions.push(this.diagnosticCollection);

        // Initialize debounced lint
        const debounceMs = configManager.get<number>('linting.debounceMs') ?? 500;
        this.debouncedLint = debounce(
            (doc: vscode.TextDocument) => this.lintDocument(doc),
            debounceMs
        );

        // Register event handlers
        this.registerEventHandlers();

        this.log.info('Compliance linter initialized');
    }

    // =========================================================================
    // Event Handlers
    // =========================================================================

    /**
     * Register document event handlers.
     */
    private registerEventHandlers(): void {
        // Lint on document open
        this.disposables.push(
            vscode.workspace.onDidOpenTextDocument((doc) => {
                if (this.shouldLint(doc) && configManager.isLintingEnabled()) {
                    this.lintDocument(doc);
                }
            })
        );

        // Lint on document save
        this.disposables.push(
            vscode.workspace.onDidSaveTextDocument((doc) => {
                if (this.shouldLint(doc) && configManager.isLintOnSaveEnabled()) {
                    this.lintDocument(doc);
                }
            })
        );

        // Lint on document change (debounced)
        this.disposables.push(
            vscode.workspace.onDidChangeTextDocument((e) => {
                if (this.shouldLint(e.document) && configManager.isLintOnTypeEnabled()) {
                    this.debouncedLint(e.document);
                }
            })
        );

        // Clear diagnostics on document close
        this.disposables.push(
            vscode.workspace.onDidCloseTextDocument((doc) => {
                this.clearDiagnostics(doc);
                this.violationMap.delete(doc.uri.toString());
            })
        );

        // Re-lint on configuration change
        this.disposables.push(
            configManager.onDidChange((e) => {
                if (e.key === 'jurisdiction' || e.key === 'regulations') {
                    this.lintAllOpen();
                }
            })
        );
    }

    // =========================================================================
    // Linting Logic
    // =========================================================================

    /**
     * Check if a document should be linted.
     */
    private shouldLint(document: vscode.TextDocument): boolean {
        const supportedLanguages = ['python', 'rust', 'typescript', 'javascript', 'helix'];
        return supportedLanguages.includes(document.languageId);
    }

    /**
     * Lint a single document.
     */
    async lintDocument(document: vscode.TextDocument): Promise<ComplianceReport | undefined> {
        if (!configManager.isLintingEnabled()) {
            return undefined;
        }

        if (!this.shouldLint(document)) {
            return undefined;
        }

        const uri = document.uri.toString();
        const startTime = Date.now();

        this.log.debug(`Linting: ${document.fileName}`);
        this.onDidStartLintEmitter.fire(document);

        // Cancel any pending lint for this document
        const pending = this.pendingLints.get(uri);
        if (pending) {
            pending.cancel();
        }

        // Create cancellation token
        const tokenSource = new vscode.CancellationTokenSource();
        this.pendingLints.set(uri, tokenSource);

        try {
            // Get configuration
            const jurisdiction = configManager.getJurisdiction();
            const regulations = configManager.getRegulations();

            // Execute CLI
            const result = await aethelCli.checkCompliance(
                document.fileName,
                jurisdiction,
                regulations,
                { cancellation: tokenSource.token }
            );

            if (tokenSource.token.isCancellationRequested) {
                return undefined;
            }

            if (!result.success || !result.data) {
                // CLI failed - show error diagnostic
                if (result.error) {
                    this.log.warn(`Lint failed: ${result.error.message}`);
                    this.setCliErrorDiagnostic(document, result.error.message);
                }
                return undefined;
            }

            const report = result.data;

            // Update diagnostics
            const diagnostics = this.violationsToDiagnostics(report.violations, document);
            this.diagnosticCollection.set(document.uri, diagnostics);

            // Store violations for quick access
            this.violationMap.set(uri, report.violations);

            // Update stats
            const duration = Date.now() - startTime;
            this.updateStats(duration, report.violations.length);

            // Fire events
            this.onDidUpdateViolationsEmitter.fire(uri);
            this.onDidEndLintEmitter.fire({ document, report });

            this.log.debug(`Lint complete: ${report.violations.length} violations in ${duration}ms`);

            return report;

        } catch (error) {
            this.log.error('Lint error', error);
            return undefined;
        } finally {
            this.pendingLints.delete(uri);
        }
    }

    /**
     * Lint all open documents.
     */
    async lintAllOpen(): Promise<void> {
        this.log.info('Linting all open documents...');

        const documents = vscode.workspace.textDocuments.filter((doc) =>
            this.shouldLint(doc)
        );

        await Promise.all(documents.map((doc) => this.lintDocument(doc)));
    }

    /**
     * Lint the active document.
     */
    async lintActiveDocument(): Promise<ComplianceReport | undefined> {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            return undefined;
        }

        return this.lintDocument(editor.document);
    }

    /**
     * Lint entire workspace.
     */
    async lintWorkspace(
        progress?: vscode.Progress<{ message?: string; increment?: number }>
    ): Promise<ComplianceReport | undefined> {
        this.log.info('Linting workspace...');

        const jurisdiction = configManager.getJurisdiction();
        const regulations = configManager.getRegulations();

        const tokenSource = new vscode.CancellationTokenSource();

        try {
            const result = await aethelCli.checkWorkspaceCompliance(
                jurisdiction,
                regulations,
                { cancellation: tokenSource.token }
            );

            if (result.success && result.data) {
                // Distribute violations to documents
                this.distributeViolations(result.data.violations);
                return result.data;
            }

            return undefined;
        } catch (error) {
            this.log.error('Workspace lint error', error);
            return undefined;
        }
    }

    // =========================================================================
    // Diagnostics
    // =========================================================================

    /**
     * Convert violations to VS Code diagnostics.
     */
    private violationsToDiagnostics(
        violations: ComplianceViolation[],
        document: vscode.TextDocument
    ): AethelredDiagnostic[] {
        return violations.map((violation) => {
            // Create range
            const startLine = Math.max(0, violation.line - 1);
            const endLine = violation.endLine ? violation.endLine - 1 : startLine;
            const startCol = Math.max(0, (violation.column ?? 1) - 1);
            const endCol = violation.endColumn ?? document.lineAt(endLine).text.length;

            const range = new vscode.Range(startLine, startCol, endLine, endCol);

            // Create diagnostic
            const diagnostic: AethelredDiagnostic = new vscode.Diagnostic(
                range,
                this.formatDiagnosticMessage(violation),
                this.mapSeverity(violation.severity)
            );

            // Add metadata
            diagnostic.source = 'Aethelred';
            diagnostic.code = this.formatDiagnosticCode(violation);
            diagnostic.violation = violation;
            diagnostic.fixes = violation.fix ? [violation.fix, ...(violation.additionalFixes ?? [])] : [];

            // Add related information
            if (violation.relatedViolations?.length) {
                diagnostic.relatedInformation = violation.relatedViolations.map((id) => {
                    const related = violations.find((v) => v.id === id);
                    if (related) {
                        return new vscode.DiagnosticRelatedInformation(
                            new vscode.Location(
                                document.uri,
                                new vscode.Position(related.line - 1, 0)
                            ),
                            related.message
                        );
                    }
                    return null;
                }).filter(Boolean) as vscode.DiagnosticRelatedInformation[];
            }

            // Add tags
            if (violation.severity === 'hint') {
                diagnostic.tags = [vscode.DiagnosticTag.Unnecessary];
            }

            return diagnostic;
        });
    }

    /**
     * Format diagnostic message.
     */
    private formatDiagnosticMessage(violation: ComplianceViolation): string {
        const emoji = this.getCategoryEmoji(violation.category);
        let message = `${emoji} ${violation.message}`;

        if (violation.regulation) {
            message += ` [${violation.regulation}]`;
        }

        return message;
    }

    /**
     * Format diagnostic code.
     */
    private formatDiagnosticCode(violation: ComplianceViolation): {
        value: string;
        target: vscode.Uri;
    } {
        const code = violation.legalReference?.article ?? violation.regulation;
        const url = violation.legalReference?.url ?? `https://docs.aethelred.io/violations/${violation.category}`;

        return {
            value: code,
            target: vscode.Uri.parse(url),
        };
    }

    /**
     * Map severity to VS Code diagnostic severity.
     */
    private mapSeverity(severity: ViolationSeverity): vscode.DiagnosticSeverity {
        const mapping: Record<ViolationSeverity, vscode.DiagnosticSeverity> = {
            critical: vscode.DiagnosticSeverity.Error,
            error: vscode.DiagnosticSeverity.Error,
            warning: vscode.DiagnosticSeverity.Warning,
            info: vscode.DiagnosticSeverity.Information,
            hint: vscode.DiagnosticSeverity.Hint,
        };
        return mapping[severity] ?? vscode.DiagnosticSeverity.Error;
    }

    /**
     * Get emoji for violation category.
     */
    private getCategoryEmoji(category: string): string {
        const emojis: Record<string, string> = {
            'data-sovereignty': '🛡️',
            'cross-border-transfer': '🌍',
            'consent': '✋',
            'retention': '⏰',
            'encryption': '🔐',
            'access-control': '🔑',
            'audit-logging': '📋',
            'data-minimization': '📉',
            'purpose-limitation': '🎯',
            'tee-requirement': '🔒',
            'hardware-attestation': '💻',
            'ai-transparency': '🤖',
            'model-governance': '📊',
        };
        return emojis[category] ?? '⚠️';
    }

    /**
     * Set a CLI error diagnostic.
     */
    private setCliErrorDiagnostic(document: vscode.TextDocument, message: string): void {
        const diagnostic = new vscode.Diagnostic(
            new vscode.Range(0, 0, 0, 0),
            `Aethelred CLI Error: ${message}`,
            vscode.DiagnosticSeverity.Warning
        );
        diagnostic.source = 'Aethelred';
        this.diagnosticCollection.set(document.uri, [diagnostic]);
    }

    /**
     * Clear diagnostics for a document.
     */
    clearDiagnostics(document: vscode.TextDocument): void {
        this.diagnosticCollection.delete(document.uri);
    }

    /**
     * Clear all diagnostics.
     */
    clearAllDiagnostics(): void {
        this.diagnosticCollection.clear();
        this.violationMap.clear();
    }

    /**
     * Distribute violations to individual documents.
     */
    private distributeViolations(violations: ComplianceViolation[]): void {
        // Group by file
        const byFile = new Map<string, ComplianceViolation[]>();

        for (const violation of violations) {
            const key = violation.file;
            if (!byFile.has(key)) {
                byFile.set(key, []);
            }
            byFile.get(key)!.push(violation);
        }

        // Update diagnostics for each file
        for (const [file, fileViolations] of byFile) {
            const uri = vscode.Uri.file(file);
            const document = vscode.workspace.textDocuments.find(
                (doc) => doc.uri.fsPath === file
            );

            if (document) {
                const diagnostics = this.violationsToDiagnostics(fileViolations, document);
                this.diagnosticCollection.set(uri, diagnostics);
                this.violationMap.set(uri.toString(), fileViolations);
            }
        }
    }

    // =========================================================================
    // Query Methods
    // =========================================================================

    /**
     * Get violations for a document.
     */
    getViolations(uri: vscode.Uri): ComplianceViolation[] {
        return this.violationMap.get(uri.toString()) ?? [];
    }

    /**
     * Get all violations.
     */
    getAllViolations(): ComplianceViolation[] {
        const all: ComplianceViolation[] = [];
        for (const violations of this.violationMap.values()) {
            all.push(...violations);
        }
        return all;
    }

    /**
     * Get violation at a specific position.
     */
    getViolationAtPosition(uri: vscode.Uri, position: vscode.Position): ComplianceViolation | undefined {
        const violations = this.getViolations(uri);
        return violations.find((v) => {
            const startLine = v.line - 1;
            const endLine = (v.endLine ?? v.line) - 1;
            return position.line >= startLine && position.line <= endLine;
        });
    }

    /**
     * Get diagnostics for a document.
     */
    getDiagnostics(uri: vscode.Uri): readonly vscode.Diagnostic[] {
        return this.diagnosticCollection.get(uri) ?? [];
    }

    /**
     * Get lint statistics.
     */
    getStats(): LintStats {
        return { ...this.stats };
    }

    /**
     * Check if document has violations.
     */
    hasViolations(uri: vscode.Uri): boolean {
        const violations = this.violationMap.get(uri.toString());
        return violations !== undefined && violations.length > 0;
    }

    /**
     * Count violations by severity.
     */
    countBySeverity(): Record<ViolationSeverity, number> {
        const counts: Record<ViolationSeverity, number> = {
            critical: 0,
            error: 0,
            warning: 0,
            info: 0,
            hint: 0,
        };

        for (const violations of this.violationMap.values()) {
            for (const v of violations) {
                counts[v.severity]++;
            }
        }

        return counts;
    }

    // =========================================================================
    // Stats
    // =========================================================================

    /**
     * Update lint statistics.
     */
    private updateStats(durationMs: number, violationCount: number): void {
        this.stats.totalLints++;
        this.stats.totalViolations += violationCount;
        this.stats.lastLintTime = new Date();

        // Calculate rolling average
        this.stats.averageDurationMs =
            (this.stats.averageDurationMs * (this.stats.totalLints - 1) + durationMs) /
            this.stats.totalLints;
    }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    /**
     * Enable linting.
     */
    enable(): void {
        this.log.info('Linting enabled');
        this.lintAllOpen();
    }

    /**
     * Disable linting.
     */
    disable(): void {
        this.log.info('Linting disabled');
        this.clearAllDiagnostics();

        // Cancel pending lints
        for (const [, tokenSource] of this.pendingLints) {
            tokenSource.cancel();
        }
        this.pendingLints.clear();
    }

    /**
     * Dispose resources.
     */
    dispose(): void {
        this.disable();
        this.diagnosticCollection.dispose();
        this.onDidUpdateViolationsEmitter.dispose();
        this.onDidStartLintEmitter.dispose();
        this.onDidEndLintEmitter.dispose();
        this.disposables.forEach((d) => d.dispose());
    }
}
