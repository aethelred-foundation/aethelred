/**
 * Aethelred VS Code Extension - Entry Point
 *
 * The Aethelred Sovereign Copilot - Enterprise-grade compliance linting
 * and sovereignty enforcement for AI development.
 *
 * This extension moves compliance checks left, allowing developers to see
 * regulatory violations as they type, not after deployment.
 *
 * Features:
 * - Real-time compliance linting with quick fixes
 * - Cost estimation for sovereign function execution
 * - Digital seal generation and verification
 * - TEE simulator integration
 * - Network connectivity and seal management
 *
 * Architecture:
 * The extension uses the 'aethel' CLI as its brain, spawning it in the
 * background for all compliance checks and operations.
 */

import * as vscode from 'vscode';

// Services
import { aethelCli, AethelCli } from './services/cli';

// Diagnostics
import { ComplianceLinter } from './diagnostics/linter';
import { registerCodeActionProviders } from './diagnostics/codeActions';

// Providers
import { registerHoverProviders } from './providers/hover';
import { registerCodeLensProviders, AethelredCodeLensProvider } from './providers/codeLens';

// Views
import { StatusBarManager } from './views/statusBar';

// Utils
import { Logger, logger, LogLevel } from './utils/logger';
import { ConfigManager, configManager } from './utils/config';

// Types
import { Jurisdiction, ComplianceReport } from './types';

/**
 * Extension context holder for global access.
 */
let extensionContext: vscode.ExtensionContext;

/**
 * Core components.
 */
let linter: ComplianceLinter;
let statusBar: StatusBarManager;
let codeLensProvider: AethelredCodeLensProvider;

/**
 * Activate the extension.
 */
export async function activate(context: vscode.ExtensionContext): Promise<void> {
    extensionContext = context;

    logger.info('Activating Aethelred Sovereign Copilot...');

    // Set log level from configuration
    logger.setLevel(configManager.getLogLevel());

    try {
        // Initialize CLI
        const cliAvailable = await aethelCli.initialize();
        if (!cliAvailable) {
            logger.warn('Aethelred CLI not found. Some features will be limited.');
            vscode.window.showWarningMessage(
                'Aethelred CLI not found. Install with: cargo install aethelred-cli',
                'Install Instructions'
            ).then((selection) => {
                if (selection === 'Install Instructions') {
                    vscode.env.openExternal(vscode.Uri.parse('https://docs.aethelred.io/cli/install'));
                }
            });
        }

        // Initialize linter
        linter = new ComplianceLinter(context);
        context.subscriptions.push(linter);

        // Initialize status bar
        statusBar = new StatusBarManager(linter);
        statusBar.setCliAvailable(cliAvailable, aethelCli.getCachedVersion() ?? undefined);
        context.subscriptions.push(statusBar);

        // Register providers
        registerHoverProviders(context);
        codeLensProvider = registerCodeLensProviders(context, linter);
        registerCodeActionProviders(context, linter);

        // Register commands
        registerCommands(context);

        // Lint open documents
        if (cliAvailable && configManager.isLintingEnabled()) {
            linter.lintAllOpen();
        }

        // Show activation message
        const jurisdictionInfo = configManager.getJurisdictionInfo(configManager.getJurisdiction());
        logger.info(`Aethelred Sovereign Copilot activated (${jurisdictionInfo.flag} ${jurisdictionInfo.name})`);

        // Check for project configuration
        checkProjectConfiguration();

    } catch (error) {
        logger.error('Failed to activate extension', error);
        vscode.window.showErrorMessage('Failed to activate Aethelred Sovereign Copilot. Check the output panel for details.');
    }
}

/**
 * Deactivate the extension.
 */
export function deactivate(): void {
    logger.info('Deactivating Aethelred Sovereign Copilot...');

    // Cancel any running CLI commands
    aethelCli.cancelAll();

    // Dispose components
    aethelCli.dispose();
    Logger.getInstance().dispose();
    ConfigManager.getInstance().dispose();

    logger.info('Aethelred Sovereign Copilot deactivated');
}

/**
 * Register extension commands.
 */
function registerCommands(context: vscode.ExtensionContext): void {
    // Compliance commands
    context.subscriptions.push(
        vscode.commands.registerCommand('aethelred.checkCompliance', checkCompliance),
        vscode.commands.registerCommand('aethelred.checkCurrentFile', checkCurrentFile),
        vscode.commands.registerCommand('aethelred.showComplianceReport', showComplianceReport),
        vscode.commands.registerCommand('aethelred.toggleRealTimeLinting', toggleRealTimeLinting),
    );

    // Jurisdiction commands
    context.subscriptions.push(
        vscode.commands.registerCommand('aethelred.setJurisdiction', setJurisdiction),
    );

    // Hardware commands
    context.subscriptions.push(
        vscode.commands.registerCommand('aethelred.simulateHardware', simulateHardware),
        vscode.commands.registerCommand('aethelred.selectHardware', selectHardware),
    );

    // Seal commands
    context.subscriptions.push(
        vscode.commands.registerCommand('aethelred.generateSeal', generateSeal),
    );

    // Project commands
    context.subscriptions.push(
        vscode.commands.registerCommand('aethelred.initProject', initProject),
        vscode.commands.registerCommand('aethelred.openDashboard', openDashboard),
    );

    // Network commands
    context.subscriptions.push(
        vscode.commands.registerCommand('aethelred.connectToNetwork', connectToNetwork),
    );

    // Utility commands
    context.subscriptions.push(
        vscode.commands.registerCommand('aethelred.explainViolation', explainViolation),
        vscode.commands.registerCommand('aethelred.showQuickFixes', showQuickFixes),
        vscode.commands.registerCommand('aethelred.exportAuditLog', exportAuditLog),
        vscode.commands.registerCommand('aethelred.refreshComplianceView', refreshComplianceView),
        vscode.commands.registerCommand('aethelred.runFixCommands', runFixCommands),
    );
}

// =============================================================================
// Command Implementations
// =============================================================================

/**
 * Run full compliance scan on workspace.
 */
async function checkCompliance(): Promise<void> {
    logger.info('Running full compliance scan...');

    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: 'Aethelred Compliance Scan',
            cancellable: true,
        },
        async (progress, token) => {
            progress.report({ message: 'Scanning workspace...' });

            const report = await linter.lintWorkspace(progress);

            if (token.isCancellationRequested) {
                return;
            }

            if (report) {
                showComplianceSummary(report);
            } else {
                vscode.window.showWarningMessage('Compliance scan did not produce results');
            }
        }
    );
}

/**
 * Check current file.
 */
async function checkCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
    }

    logger.info(`Checking file: ${editor.document.fileName}`);

    statusBar.setLoading();

    try {
        const report = await linter.lintDocument(editor.document);
        statusBar.setActive();

        if (report) {
            const violations = report.violations.length;
            if (violations === 0) {
                vscode.window.showInformationMessage('$(check) No compliance violations detected');
            } else {
                vscode.window.showWarningMessage(
                    `$(warning) ${violations} compliance violation${violations === 1 ? '' : 's'} detected`,
                    'Show Report'
                ).then((selection) => {
                    if (selection === 'Show Report') {
                        showComplianceReport();
                    }
                });
            }
        }
    } catch (error) {
        statusBar.setError();
        logger.error('Check failed', error);
    }
}

/**
 * Show compliance report.
 */
async function showComplianceReport(): Promise<void> {
    const violations = linter.getAllViolations();

    if (violations.length === 0) {
        vscode.window.showInformationMessage('No compliance violations detected');
        return;
    }

    // Create a quick pick with violations
    const items = violations.map((v) => ({
        label: `$(${v.severity === 'error' || v.severity === 'critical' ? 'error' : 'warning'}) ${v.message}`,
        description: `${v.regulation} | Line ${v.line}`,
        detail: v.description,
        violation: v,
    }));

    const selected = await vscode.window.showQuickPick(items, {
        placeHolder: 'Select a violation to navigate to',
        matchOnDescription: true,
        matchOnDetail: true,
    });

    if (selected) {
        const uri = vscode.Uri.file(selected.violation.file);
        const position = new vscode.Position(selected.violation.line - 1, selected.violation.column - 1);

        const doc = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(doc);
        editor.selection = new vscode.Selection(position, position);
        editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenter);
    }
}

/**
 * Toggle real-time linting.
 */
async function toggleRealTimeLinting(): Promise<void> {
    const current = configManager.isLintingEnabled();
    await configManager.set('linting.enabled', !current);

    if (!current) {
        linter.enable();
        vscode.window.showInformationMessage('Aethelred real-time linting enabled');
    } else {
        linter.disable();
        vscode.window.showInformationMessage('Aethelred real-time linting disabled');
    }
}

/**
 * Set jurisdiction.
 */
async function setJurisdiction(): Promise<void> {
    const jurisdictions: Jurisdiction[] = [
        'Global', 'UAE', 'UAE-ADGM', 'UAE-DIFC', 'Saudi-Arabia',
        'EU', 'EU-Germany', 'EU-France', 'UK',
        'US', 'US-California', 'US-NewYork',
        'Singapore', 'China', 'Japan', 'Australia', 'India', 'Brazil', 'Canada',
    ];

    const items = jurisdictions.map((j) => {
        const info = configManager.getJurisdictionInfo(j);
        return {
            label: `${info.flag} ${j}`,
            description: info.name,
            jurisdiction: j,
        };
    });

    const current = configManager.getJurisdiction();
    const currentIndex = jurisdictions.indexOf(current);

    const selected = await vscode.window.showQuickPick(items, {
        placeHolder: 'Select jurisdiction for compliance checks',
        matchOnDescription: true,
    });

    if (selected) {
        await configManager.setJurisdiction(selected.jurisdiction);
        vscode.window.showInformationMessage(
            `Jurisdiction set to ${selected.label}. Re-linting open files...`
        );
        linter.lintAllOpen();
    }
}

/**
 * Start TEE simulator.
 */
async function simulateHardware(): Promise<void> {
    if (!configManager.isSimulatorEnabled()) {
        vscode.window.showWarningMessage('TEE simulator is disabled in settings');
        return;
    }

    const hardware = await vscode.window.showQuickPick([
        { label: '$(lock) Intel SGX', value: 'intel-sgx' },
        { label: '$(lock) Intel TDX', value: 'intel-tdx' },
        { label: '$(lock) AMD SEV-SNP', value: 'amd-sev-snp' },
        { label: '$(cloud) AWS Nitro', value: 'aws-nitro' },
    ], {
        placeHolder: 'Select TEE to simulate',
    });

    if (!hardware) {
        return;
    }

    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: `Starting ${hardware.label} simulator...`,
            cancellable: false,
        },
        async () => {
            const result = await aethelCli.startSimulator(hardware.value as any);

            if (result.success && result.data) {
                statusBar.setTeeSimulatorRunning(true);
                vscode.window.showInformationMessage(
                    `TEE simulator started on port ${result.data.port}`
                );
            } else {
                vscode.window.showErrorMessage(
                    `Failed to start simulator: ${result.error?.message}`
                );
            }
        }
    );
}

/**
 * Select hardware target.
 */
async function selectHardware(): Promise<void> {
    const hardware = await vscode.window.showQuickPick([
        { label: '$(gear) Auto-detect', value: 'auto' },
        { label: '$(server) Generic', value: 'generic' },
        { label: '$(lock) Intel SGX', value: 'intel-sgx' },
        { label: '$(lock) Intel SGX DCAP', value: 'intel-sgx-dcap' },
        { label: '$(lock) Intel TDX', value: 'intel-tdx' },
        { label: '$(lock) AMD SEV', value: 'amd-sev' },
        { label: '$(lock) AMD SEV-SNP', value: 'amd-sev-snp' },
        { label: '$(cloud) AWS Nitro', value: 'aws-nitro' },
        { label: '$(cloud) Azure Confidential', value: 'azure-confidential' },
        { label: '$(cloud) GCP Confidential', value: 'gcp-confidential' },
        { label: '$(circuit-board) NVIDIA H100', value: 'nvidia-h100' },
    ], {
        placeHolder: 'Select target hardware',
    });

    if (hardware) {
        await configManager.set('hardware.target', hardware.value);
        vscode.window.showInformationMessage(`Target hardware set to ${hardware.label}`);
        codeLensProvider.refresh();
    }
}

/**
 * Generate digital seal.
 */
async function generateSeal(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
    }

    // Check for violations first
    const violations = linter.getViolations(editor.document.uri);
    if (violations.length > 0) {
        const proceed = await vscode.window.showWarningMessage(
            `${violations.length} compliance violations detected. Generate seal anyway?`,
            'Yes', 'No'
        );
        if (proceed !== 'Yes') {
            return;
        }
    }

    vscode.window.showInformationMessage(
        'Digital seal generation requires network connectivity. Feature coming soon!'
    );
}

/**
 * Initialize Aethelred project.
 */
async function initProject(): Promise<void> {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
        vscode.window.showWarningMessage('No workspace folder open');
        return;
    }

    const template = await vscode.window.showQuickPick([
        { label: '$(file) Default', value: 'default', description: 'Basic Aethelred project' },
        { label: '$(graph) Finance', value: 'finance', description: 'Financial services template' },
        { label: '$(heart) Healthcare', value: 'healthcare', description: 'HIPAA-compliant template' },
        { label: '$(globe) Green Energy', value: 'green-energy', description: 'ESG-focused template' },
    ], {
        placeHolder: 'Select project template',
    });

    if (!template) {
        return;
    }

    const jurisdiction = await vscode.window.showQuickPick(
        ['Global', 'UAE', 'EU', 'US', 'Singapore', 'China'].map((j) => ({
            label: configManager.getJurisdictionInfo(j as Jurisdiction).flag + ' ' + j,
            value: j,
        })),
        { placeHolder: 'Select default jurisdiction' }
    );

    if (!jurisdiction) {
        return;
    }

    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: 'Initializing Aethelred project...',
        },
        async () => {
            const result = await aethelCli.initProject(
                template.value,
                jurisdiction.value as Jurisdiction,
                { cwd: folder.uri.fsPath }
            );

            if (result.success) {
                vscode.window.showInformationMessage(
                    'Aethelred project initialized successfully!',
                    'Open Config'
                ).then((selection) => {
                    if (selection === 'Open Config' && result.data) {
                        vscode.workspace.openTextDocument(result.data.configPath)
                            .then((doc) => vscode.window.showTextDocument(doc));
                    }
                });
            } else {
                vscode.window.showErrorMessage(
                    `Failed to initialize project: ${result.error?.message}`
                );
            }
        }
    );
}

/**
 * Open dashboard.
 */
async function openDashboard(): Promise<void> {
    // For now, show compliance report
    // In the future, this could open a webview dashboard
    await showComplianceReport();
}

/**
 * Connect to network.
 */
async function connectToNetwork(): Promise<void> {
    const chain = configManager.getNetworkChain();

    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: `Connecting to Aethelred ${chain}...`,
        },
        async () => {
            const result = await aethelCli.getNetworkStatus();

            if (result.success && result.data) {
                statusBar.setNetworkConnected(true);
                vscode.window.showInformationMessage(
                    `Connected to ${chain} (Block: ${result.data.blockHeight})`
                );
            } else {
                statusBar.setNetworkConnected(false);
                vscode.window.showErrorMessage(
                    `Failed to connect: ${result.error?.message}`
                );
            }
        }
    );
}

/**
 * Explain a violation.
 */
async function explainViolation(violation: any): Promise<void> {
    if (!violation) {
        vscode.window.showWarningMessage('No violation to explain');
        return;
    }

    const md = new vscode.MarkdownString();
    md.isTrusted = true;

    md.appendMarkdown(`## ${violation.message}\n\n`);
    md.appendMarkdown(`**Regulation:** ${violation.regulation}\n\n`);
    md.appendMarkdown(`**Category:** ${violation.category}\n\n`);
    md.appendMarkdown(`**Severity:** ${violation.severity}\n\n`);

    if (violation.description) {
        md.appendMarkdown(`### Description\n\n${violation.description}\n\n`);
    }

    if (violation.legalReference) {
        md.appendMarkdown(`### Legal Reference\n\n`);
        md.appendMarkdown(`**Article:** ${violation.legalReference.article}\n\n`);
        md.appendMarkdown(`${violation.legalReference.summary}\n\n`);
        md.appendMarkdown(`[View Full Text](${violation.legalReference.url})\n\n`);
    }

    if (violation.fix) {
        md.appendMarkdown(`### Suggested Fix\n\n${violation.fix.description}\n\n`);
    }

    // Show in a webview or hover
    vscode.window.showInformationMessage(violation.message, 'View Documentation').then((selection) => {
        if (selection === 'View Documentation' && violation.legalReference?.url) {
            vscode.env.openExternal(vscode.Uri.parse(violation.legalReference.url));
        }
    });
}

/**
 * Show quick fixes.
 */
async function showQuickFixes(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        return;
    }

    // Trigger the built-in quick fix command
    await vscode.commands.executeCommand('editor.action.quickFix');
}

/**
 * Export audit log.
 */
async function exportAuditLog(): Promise<void> {
    const violations = linter.getAllViolations();
    const stats = linter.getStats();

    const auditLog = {
        timestamp: new Date().toISOString(),
        jurisdiction: configManager.getJurisdiction(),
        regulations: configManager.getRegulations(),
        statistics: stats,
        violations: violations,
    };

    const content = JSON.stringify(auditLog, null, 2);

    const uri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file('aethelred-audit.json'),
        filters: { 'JSON': ['json'] },
    });

    if (uri) {
        await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf-8'));
        vscode.window.showInformationMessage(`Audit log exported to ${uri.fsPath}`);
    }
}

/**
 * Refresh compliance view.
 */
async function refreshComplianceView(): Promise<void> {
    await linter.lintAllOpen();
    codeLensProvider.refresh();
}

/**
 * Run fix commands.
 */
async function runFixCommands(commands: any[]): Promise<void> {
    for (const cmd of commands) {
        try {
            await vscode.commands.executeCommand(cmd.command, ...(cmd.args || []));
        } catch (error) {
            logger.error(`Failed to run fix command: ${cmd.command}`, error);
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Check for project configuration.
 */
async function checkProjectConfiguration(): Promise<void> {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders) {
        return;
    }

    // Look for aethelred.toml
    const configFiles = await vscode.workspace.findFiles('**/aethelred.toml', '**/node_modules/**', 1);

    if (configFiles.length === 0) {
        // No config file found
        logger.debug('No aethelred.toml found in workspace');
    }
}

/**
 * Show compliance summary.
 */
function showComplianceSummary(report: ComplianceReport): void {
    const summary = report.summary;
    const total = summary.total;

    if (total === 0) {
        vscode.window.showInformationMessage(
            `$(check) Compliance scan complete. No violations detected. Score: ${report.score}/100`
        );
    } else {
        const message = `Compliance scan complete. ${total} violation${total === 1 ? '' : 's'} found. Score: ${report.score}/100`;

        vscode.window.showWarningMessage(message, 'Show Report', 'Dismiss').then((selection) => {
            if (selection === 'Show Report') {
                showComplianceReport();
            }
        });
    }
}
