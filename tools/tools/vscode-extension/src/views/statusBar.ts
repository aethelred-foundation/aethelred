/**
 * Aethelred VS Code Extension - Status Bar
 *
 * Provides a status bar item showing current jurisdiction,
 * compliance status, and quick access to Aethelred features.
 */

import * as vscode from 'vscode';
import { ComplianceLinter } from '../diagnostics/linter';
import { aethCli } from '../services/cli';
import { configManager } from '../utils/config';
import { logger, CategoryLogger } from '../utils/logger';
import { ExtensionStatus, Jurisdiction, ComplianceSummary } from '../types';

/**
 * Status bar manager for Aethelred extension.
 */
export class StatusBarManager {
    private readonly log: CategoryLogger;

    // Status bar items
    private readonly mainItem: vscode.StatusBarItem;
    private readonly violationItem: vscode.StatusBarItem;
    private readonly networkItem: vscode.StatusBarItem;

    // State
    private status: ExtensionStatus = {
        state: 'loading',
        cliAvailable: false,
        networkConnected: false,
        jurisdiction: 'Global',
        violations: {
            total: 0,
            critical: 0,
            error: 0,
            warning: 0,
            info: 0,
            hint: 0,
            fixed: 0,
            suppressed: 0,
        },
        teeSimulatorRunning: false,
    };

    private readonly disposables: vscode.Disposable[] = [];

    constructor(private readonly linter: ComplianceLinter) {
        this.log = logger.createChild('StatusBar');

        // Create main status bar item (shield icon)
        this.mainItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            1000
        );
        this.mainItem.command = 'aethelred.openDashboard';
        this.mainItem.name = 'Aethelred Sovereign';

        // Create violation count item
        this.violationItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            999
        );
        this.violationItem.command = 'aethelred.showComplianceReport';
        this.violationItem.name = 'Aethelred Violations';

        // Create network status item
        this.networkItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            998
        );
        this.networkItem.command = 'aethelred.connectToNetwork';
        this.networkItem.name = 'Aethelred Network';

        // Subscribe to events
        this.subscribeToEvents();

        // Initial update
        this.initialize();
    }

    /**
     * Initialize status bar.
     */
    private async initialize(): Promise<void> {
        this.log.info('Initializing status bar...');

        // Check CLI availability
        this.status.cliAvailable = aethCli.isAvailable();
        this.status.cliVersion = aethCli.getCachedVersion() ?? undefined;

        // Get jurisdiction
        this.status.jurisdiction = configManager.getJurisdiction();

        // Update state
        this.status.state = this.status.cliAvailable ? 'active' : 'error';

        // Update display
        this.update();

        // Show items if enabled
        if (configManager.shouldShowStatusBar()) {
            this.show();
        }
    }

    /**
     * Subscribe to relevant events.
     */
    private subscribeToEvents(): void {
        // Linter updates
        this.disposables.push(
            this.linter.onDidUpdateViolations(() => {
                this.updateViolationCount();
            })
        );

        // Configuration changes
        this.disposables.push(
            configManager.onDidChange((e) => {
                if (e.key === 'jurisdiction') {
                    this.status.jurisdiction = e.newValue as Jurisdiction;
                    this.update();
                }
                if (e.key === 'ui.showStatusBar') {
                    if (e.newValue) {
                        this.show();
                    } else {
                        this.hide();
                    }
                }
            })
        );
    }

    /**
     * Update status bar display.
     */
    private update(): void {
        this.updateMainItem();
        this.updateViolationItem();
        this.updateNetworkItem();
    }

    /**
     * Update main status bar item.
     */
    private updateMainItem(): void {
        const jurisdictionInfo = configManager.getJurisdictionInfo(this.status.jurisdiction);

        switch (this.status.state) {
            case 'active':
                this.mainItem.text = `$(shield) ${jurisdictionInfo.flag} ${this.status.jurisdiction}`;
                this.mainItem.tooltip = new vscode.MarkdownString(this.buildMainTooltip());
                this.mainItem.backgroundColor = undefined;
                break;

            case 'loading':
                this.mainItem.text = '$(loading~spin) Aethelred';
                this.mainItem.tooltip = 'Initializing Aethelred Sovereign Copilot...';
                this.mainItem.backgroundColor = undefined;
                break;

            case 'error':
                this.mainItem.text = '$(warning) Aethelred';
                this.mainItem.tooltip = 'Aethelred CLI not found. Click to configure.';
                this.mainItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
                break;

            case 'inactive':
                this.mainItem.text = '$(circle-slash) Aethelred';
                this.mainItem.tooltip = 'Aethelred is inactive. Click to enable.';
                this.mainItem.backgroundColor = undefined;
                break;
        }
    }

    /**
     * Build main tooltip markdown.
     */
    private buildMainTooltip(): string {
        const jurisdictionInfo = configManager.getJurisdictionInfo(this.status.jurisdiction);
        const regulations = configManager.getRegulations();

        let tooltip = `### 🛡️ Aethelred Sovereign Copilot\n\n`;
        tooltip += `**Status:** ${this.status.state === 'active' ? '$(check) Active' : '$(x) Inactive'}\n\n`;
        tooltip += `**Jurisdiction:** ${jurisdictionInfo.flag} ${jurisdictionInfo.name}\n\n`;
        tooltip += `**Regulations:** ${regulations.join(', ') || 'None'}\n\n`;

        if (this.status.cliVersion) {
            tooltip += `**CLI Version:** v${this.status.cliVersion}\n\n`;
        }

        tooltip += `---\n\n`;
        tooltip += `[$(settings) Settings](command:workbench.action.openSettings?%22aethelred%22) | `;
        tooltip += `[$(graph) Dashboard](command:aethelred.openDashboard)`;

        return tooltip;
    }

    /**
     * Update violation count item.
     */
    private updateViolationItem(): void {
        const violations = this.status.violations;
        const total = violations.total;

        if (total === 0) {
            this.violationItem.text = '$(check) 0';
            this.violationItem.tooltip = 'No compliance violations detected';
            this.violationItem.backgroundColor = undefined;
            this.violationItem.color = new vscode.ThemeColor('aethelred.compliant');
        } else if (violations.critical > 0 || violations.error > 0) {
            const count = violations.critical + violations.error;
            this.violationItem.text = `$(error) ${count}`;
            this.violationItem.tooltip = this.buildViolationTooltip();
            this.violationItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
            this.violationItem.color = undefined;
        } else {
            this.violationItem.text = `$(warning) ${total}`;
            this.violationItem.tooltip = this.buildViolationTooltip();
            this.violationItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
            this.violationItem.color = undefined;
        }
    }

    /**
     * Build violation tooltip.
     */
    private buildViolationTooltip(): string {
        const v = this.status.violations;

        let tooltip = `### Compliance Violations\n\n`;

        if (v.critical > 0) {
            tooltip += `$(error) **Critical:** ${v.critical}\n\n`;
        }
        if (v.error > 0) {
            tooltip += `$(error) **Errors:** ${v.error}\n\n`;
        }
        if (v.warning > 0) {
            tooltip += `$(warning) **Warnings:** ${v.warning}\n\n`;
        }
        if (v.info > 0) {
            tooltip += `$(info) **Info:** ${v.info}\n\n`;
        }

        tooltip += `---\n\n`;
        tooltip += `[$(eye) View All](command:aethelred.showComplianceReport)`;

        return tooltip;
    }

    /**
     * Update network status item.
     */
    private updateNetworkItem(): void {
        const chain = configManager.getNetworkChain();

        if (this.status.networkConnected) {
            this.networkItem.text = `$(plug) ${chain}`;
            this.networkItem.tooltip = `Connected to Aethelred ${chain}`;
            this.networkItem.backgroundColor = undefined;
        } else {
            this.networkItem.text = `$(debug-disconnect) ${chain}`;
            this.networkItem.tooltip = 'Not connected to Aethelred network. Click to connect.';
            this.networkItem.backgroundColor = undefined;
        }
    }

    /**
     * Update violation count from linter.
     */
    private updateViolationCount(): void {
        const counts = this.linter.countBySeverity();

        this.status.violations = {
            total: counts.critical + counts.error + counts.warning + counts.info + counts.hint,
            critical: counts.critical,
            error: counts.error,
            warning: counts.warning,
            info: counts.info,
            hint: counts.hint,
            fixed: 0,
            suppressed: 0,
        };

        this.updateViolationItem();
    }

    /**
     * Set CLI available status.
     */
    setCliAvailable(available: boolean, version?: string): void {
        this.status.cliAvailable = available;
        this.status.cliVersion = version;
        this.status.state = available ? 'active' : 'error';
        this.update();
    }

    /**
     * Set network connected status.
     */
    setNetworkConnected(connected: boolean): void {
        this.status.networkConnected = connected;
        this.updateNetworkItem();
    }

    /**
     * Set TEE simulator status.
     */
    setTeeSimulatorRunning(running: boolean): void {
        this.status.teeSimulatorRunning = running;
        // Could add an indicator for this
    }

    /**
     * Set loading state.
     */
    setLoading(): void {
        this.status.state = 'loading';
        this.updateMainItem();
    }

    /**
     * Set active state.
     */
    setActive(): void {
        this.status.state = 'active';
        this.updateMainItem();
    }

    /**
     * Set error state.
     */
    setError(message?: string): void {
        this.status.state = 'error';
        this.updateMainItem();
        if (message) {
            this.mainItem.tooltip = message;
        }
    }

    /**
     * Show status bar items.
     */
    show(): void {
        this.mainItem.show();
        this.violationItem.show();
        // Only show network item if configured
        if (configManager.getNetworkChain() !== 'local') {
            this.networkItem.show();
        }
    }

    /**
     * Hide status bar items.
     */
    hide(): void {
        this.mainItem.hide();
        this.violationItem.hide();
        this.networkItem.hide();
    }

    /**
     * Get current status.
     */
    getStatus(): ExtensionStatus {
        return { ...this.status };
    }

    /**
     * Dispose resources.
     */
    dispose(): void {
        this.mainItem.dispose();
        this.violationItem.dispose();
        this.networkItem.dispose();
        this.disposables.forEach((d) => d.dispose());
    }
}
