/**
 * Aethelred VS Code Extension - Configuration Manager
 *
 * Centralized configuration management with type safety,
 * change detection, and validation.
 */

import * as vscode from 'vscode';
import {
    AethelredConfig,
    Jurisdiction,
    Regulation,
    HardwareType,
    ViolationSeverity,
} from '../types';
import { logger } from './logger';

/**
 * Configuration change event.
 */
export interface ConfigChangeEvent {
    key: string;
    oldValue: unknown;
    newValue: unknown;
}

/**
 * Configuration manager for the Aethelred extension.
 */
export class ConfigManager {
    private static instance: ConfigManager | null = null;

    private readonly configSection = 'aethelred';
    private readonly onDidChangeEmitter = new vscode.EventEmitter<ConfigChangeEvent>();
    private cachedConfig: AethelredConfig | null = null;
    private disposables: vscode.Disposable[] = [];

    /**
     * Event fired when configuration changes.
     */
    readonly onDidChange = this.onDidChangeEmitter.event;

    private constructor() {
        // Watch for configuration changes
        this.disposables.push(
            vscode.workspace.onDidChangeConfiguration((e) => {
                if (e.affectsConfiguration(this.configSection)) {
                    this.handleConfigChange(e);
                }
            })
        );
    }

    /**
     * Get the singleton instance.
     */
    static getInstance(): ConfigManager {
        if (!ConfigManager.instance) {
            ConfigManager.instance = new ConfigManager();
        }
        return ConfigManager.instance;
    }

    /**
     * Get the complete configuration.
     */
    getConfig(): AethelredConfig {
        if (this.cachedConfig) {
            return this.cachedConfig;
        }

        const config = vscode.workspace.getConfiguration(this.configSection);

        this.cachedConfig = {
            jurisdiction: config.get<Jurisdiction>('jurisdiction') ?? 'Global',
            regulations: config.get<Regulation[]>('compliance.regulations') ?? ['GDPR'],
            linting: {
                enabled: config.get<boolean>('linting.enabled') ?? true,
                onSave: config.get<boolean>('linting.onSave') ?? true,
                onType: config.get<boolean>('linting.onType') ?? false,
                debounceMs: config.get<number>('linting.debounceMs') ?? 500,
                severity: config.get<ViolationSeverity>('linting.severity') ?? 'error',
            },
            cli: {
                path: config.get<string>('cli.path') ?? '',
                timeout: config.get<number>('cli.timeout') ?? 30000,
            },
            hardware: {
                target: config.get<HardwareType | 'auto'>('hardware.target') ?? 'auto',
                simulatorEnabled: config.get<boolean>('hardware.simulatorEnabled') ?? true,
            },
            network: {
                endpoint: config.get<string>('network.endpoint') ?? 'https://api.testnet.aethelred.io',
                chain: config.get<'mainnet' | 'testnet' | 'devnet' | 'local'>('network.chain') ?? 'testnet',
            },
            ui: {
                showStatusBar: config.get<boolean>('ui.showStatusBar') ?? true,
                showInlineHints: config.get<boolean>('ui.showInlineHints') ?? true,
                showCodeLens: config.get<boolean>('ui.showCodeLens') ?? true,
            },
            logging: {
                level: config.get<'error' | 'warn' | 'info' | 'debug' | 'trace'>('logging.level') ?? 'info',
            },
        };

        return this.cachedConfig;
    }

    /**
     * Get a specific configuration value.
     */
    get<T>(key: string, defaultValue?: T): T {
        const config = vscode.workspace.getConfiguration(this.configSection);
        return config.get<T>(key) ?? defaultValue as T;
    }

    /**
     * Set a configuration value.
     */
    async set<T>(
        key: string,
        value: T,
        target: vscode.ConfigurationTarget = vscode.ConfigurationTarget.Workspace
    ): Promise<void> {
        const config = vscode.workspace.getConfiguration(this.configSection);
        await config.update(key, value, target);
    }

    /**
     * Get the active jurisdiction.
     */
    getJurisdiction(): Jurisdiction {
        return this.getConfig().jurisdiction;
    }

    /**
     * Set the active jurisdiction.
     */
    async setJurisdiction(jurisdiction: Jurisdiction): Promise<void> {
        await this.set('jurisdiction', jurisdiction);
    }

    /**
     * Get active regulations.
     */
    getRegulations(): Regulation[] {
        return this.getConfig().regulations;
    }

    /**
     * Check if linting is enabled.
     */
    isLintingEnabled(): boolean {
        return this.getConfig().linting.enabled;
    }

    /**
     * Check if on-save linting is enabled.
     */
    isLintOnSaveEnabled(): boolean {
        return this.getConfig().linting.onSave && this.isLintingEnabled();
    }

    /**
     * Check if on-type linting is enabled.
     */
    isLintOnTypeEnabled(): boolean {
        return this.getConfig().linting.onType && this.isLintingEnabled();
    }

    /**
     * Get CLI path.
     */
    getCliPath(): string {
        return this.getConfig().cli.path;
    }

    /**
     * Get CLI timeout.
     */
    getCliTimeout(): number {
        return this.getConfig().cli.timeout;
    }

    /**
     * Get target hardware.
     */
    getTargetHardware(): HardwareType | 'auto' {
        return this.getConfig().hardware.target;
    }

    /**
     * Check if TEE simulator is enabled.
     */
    isSimulatorEnabled(): boolean {
        return this.getConfig().hardware.simulatorEnabled;
    }

    /**
     * Get network endpoint.
     */
    getNetworkEndpoint(): string {
        return this.getConfig().network.endpoint;
    }

    /**
     * Get network chain.
     */
    getNetworkChain(): string {
        return this.getConfig().network.chain;
    }

    /**
     * Check if status bar should be shown.
     */
    shouldShowStatusBar(): boolean {
        return this.getConfig().ui.showStatusBar;
    }

    /**
     * Check if inline hints should be shown.
     */
    shouldShowInlineHints(): boolean {
        return this.getConfig().ui.showInlineHints;
    }

    /**
     * Check if code lens should be shown.
     */
    shouldShowCodeLens(): boolean {
        return this.getConfig().ui.showCodeLens;
    }

    /**
     * Get log level.
     */
    getLogLevel(): string {
        return this.getConfig().logging.level;
    }

    /**
     * Handle configuration changes.
     */
    private handleConfigChange(e: vscode.ConfigurationChangeEvent): void {
        const oldConfig = this.cachedConfig;
        this.cachedConfig = null; // Invalidate cache

        const newConfig = this.getConfig();

        logger.debug('Configuration changed', {
            affected: this.configSection,
        });

        // Detect specific changes and emit events
        if (oldConfig) {
            this.emitChanges(oldConfig, newConfig);
        }

        // Update logger level
        logger.setLevel(newConfig.logging.level);
    }

    /**
     * Emit change events for modified settings.
     */
    private emitChanges(oldConfig: AethelredConfig, newConfig: AethelredConfig): void {
        if (oldConfig.jurisdiction !== newConfig.jurisdiction) {
            this.onDidChangeEmitter.fire({
                key: 'jurisdiction',
                oldValue: oldConfig.jurisdiction,
                newValue: newConfig.jurisdiction,
            });
        }

        if (JSON.stringify(oldConfig.regulations) !== JSON.stringify(newConfig.regulations)) {
            this.onDidChangeEmitter.fire({
                key: 'regulations',
                oldValue: oldConfig.regulations,
                newValue: newConfig.regulations,
            });
        }

        if (oldConfig.linting.enabled !== newConfig.linting.enabled) {
            this.onDidChangeEmitter.fire({
                key: 'linting.enabled',
                oldValue: oldConfig.linting.enabled,
                newValue: newConfig.linting.enabled,
            });
        }
    }

    /**
     * Validate the current configuration.
     */
    validate(): string[] {
        const errors: string[] = [];
        const config = this.getConfig();

        // Validate linting debounce
        if (config.linting.debounceMs < 100 || config.linting.debounceMs > 5000) {
            errors.push('Linting debounce must be between 100ms and 5000ms');
        }

        // Validate CLI timeout
        if (config.cli.timeout < 5000 || config.cli.timeout > 300000) {
            errors.push('CLI timeout must be between 5s and 300s');
        }

        // Validate network endpoint
        if (config.network.endpoint && !this.isValidUrl(config.network.endpoint)) {
            errors.push('Invalid network endpoint URL');
        }

        return errors;
    }

    /**
     * Check if a string is a valid URL.
     */
    private isValidUrl(url: string): boolean {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Get jurisdiction display info.
     */
    getJurisdictionInfo(jurisdiction: Jurisdiction): { name: string; flag: string } {
        const info: Record<Jurisdiction, { name: string; flag: string }> = {
            'Global': { name: 'Global', flag: '🌍' },
            'UAE': { name: 'United Arab Emirates', flag: '🇦🇪' },
            'UAE-ADGM': { name: 'UAE - ADGM', flag: '🇦🇪' },
            'UAE-DIFC': { name: 'UAE - DIFC', flag: '🇦🇪' },
            'Saudi-Arabia': { name: 'Saudi Arabia', flag: '🇸🇦' },
            'EU': { name: 'European Union', flag: '🇪🇺' },
            'EU-Germany': { name: 'Germany', flag: '🇩🇪' },
            'EU-France': { name: 'France', flag: '🇫🇷' },
            'UK': { name: 'United Kingdom', flag: '🇬🇧' },
            'US': { name: 'United States', flag: '🇺🇸' },
            'US-California': { name: 'California, USA', flag: '🇺🇸' },
            'US-NewYork': { name: 'New York, USA', flag: '🇺🇸' },
            'Singapore': { name: 'Singapore', flag: '🇸🇬' },
            'China': { name: 'China', flag: '🇨🇳' },
            'Japan': { name: 'Japan', flag: '🇯🇵' },
            'Australia': { name: 'Australia', flag: '🇦🇺' },
            'India': { name: 'India', flag: '🇮🇳' },
            'Brazil': { name: 'Brazil', flag: '🇧🇷' },
            'Canada': { name: 'Canada', flag: '🇨🇦' },
        };
        return info[jurisdiction] ?? { name: jurisdiction, flag: '🌍' };
    }

    /**
     * Dispose resources.
     */
    dispose(): void {
        this.onDidChangeEmitter.dispose();
        this.disposables.forEach((d) => d.dispose());
        ConfigManager.instance = null;
    }
}

// Export singleton accessor
export const configManager = ConfigManager.getInstance();
