/**
 * Aethelred VS Code Extension - Hover Provider
 *
 * Provides rich hover information for @sovereign decorators and
 * sovereign functions. Shows cost estimates, hardware requirements,
 * and compliance information on hover.
 */

import * as vscode from 'vscode';
import {
    CostEstimate,
    HardwareType,
    Jurisdiction,
    Regulation,
    SovereignFunctionInfo,
} from '../types';
import { aethelCli } from '../services/cli';
import { configManager } from '../utils/config';
import { logger, CategoryLogger } from '../utils/logger';

/**
 * Pattern matching for sovereign decorators.
 */
const SOVEREIGN_PATTERNS = {
    python: {
        decorator: /@sovereign\s*(\([^)]*\))?/g,
        function: /def\s+(\w+)\s*\([^)]*\)/g,
    },
    rust: {
        decorator: /#\[sovereign\s*(\([^)]*\))?\]/g,
        function: /fn\s+(\w+)\s*(<[^>]*>)?\s*\([^)]*\)/g,
    },
    typescript: {
        decorator: /@sovereign\s*(\([^)]*\))?/g,
        function: /(?:async\s+)?function\s+(\w+)|(\w+)\s*[=:]\s*(?:async\s+)?(?:\([^)]*\)|[^=])*=>/g,
    },
};

/**
 * Hover provider for Aethelred sovereign functions.
 */
export class AethelredHoverProvider implements vscode.HoverProvider {
    private readonly log: CategoryLogger;
    private readonly estimateCache = new Map<string, { estimate: CostEstimate; timestamp: number }>();
    private readonly cacheMaxAge = 30000; // 30 seconds

    constructor() {
        this.log = logger.createChild('Hover');
    }

    /**
     * Provide hover information.
     */
    async provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken
    ): Promise<vscode.Hover | null> {
        // Check if inline hints are enabled
        if (!configManager.shouldShowInlineHints()) {
            return null;
        }

        const line = document.lineAt(position.line).text;
        const wordRange = document.getWordRangeAtPosition(position);
        const word = document.getText(wordRange);

        // Check for @sovereign decorator
        if (this.isSovereignDecorator(word, line)) {
            return this.provideSovereignHover(document, position, token);
        }

        // Check for sovereign function name
        const functionInfo = this.findSovereignFunction(document, position);
        if (functionInfo) {
            return this.provideFunctionHover(functionInfo, token);
        }

        return null;
    }

    /**
     * Check if the word is a sovereign decorator.
     */
    private isSovereignDecorator(word: string, line: string): boolean {
        return (
            word === 'sovereign' ||
            word === '@sovereign' ||
            line.includes('@sovereign') ||
            line.includes('#[sovereign')
        );
    }

    /**
     * Find sovereign function at position.
     */
    private findSovereignFunction(
        document: vscode.TextDocument,
        position: vscode.Position
    ): SovereignFunctionInfo | null {
        // Look backwards for decorator
        let decoratorLine = -1;
        let decoratorParams: Record<string, string> = {};

        for (let i = position.line; i >= Math.max(0, position.line - 10); i--) {
            const line = document.lineAt(i).text;
            const decoratorMatch = line.match(/@sovereign\s*\(([^)]*)\)|#\[sovereign\s*\(([^)]*)\)\]/);

            if (decoratorMatch) {
                decoratorLine = i;
                decoratorParams = this.parseDecoratorParams(decoratorMatch[1] || decoratorMatch[2] || '');
                break;
            }
        }

        if (decoratorLine === -1) {
            return null;
        }

        // Look forward for function definition
        for (let i = decoratorLine; i <= Math.min(document.lineCount - 1, decoratorLine + 5); i++) {
            const line = document.lineAt(i).text;
            const functionMatch = line.match(/def\s+(\w+)|fn\s+(\w+)|function\s+(\w+)|(\w+)\s*[=:]\s*(?:async\s+)?(?:\(|function)/);

            if (functionMatch) {
                const name = functionMatch[1] || functionMatch[2] || functionMatch[3] || functionMatch[4];
                return {
                    name,
                    file: document.fileName,
                    line: i + 1,
                    column: line.indexOf(name) + 1,
                    endLine: i + 1,
                    endColumn: line.indexOf(name) + name.length + 1,
                    decoratorLine: decoratorLine + 1,
                    hardware: decoratorParams.hardware as HardwareType | undefined,
                    jurisdiction: decoratorParams.jurisdiction as Jurisdiction | undefined,
                    compliance: decoratorParams.compliance?.split(',').map((s) => s.trim()) as Regulation[] | undefined,
                };
            }
        }

        return null;
    }

    /**
     * Parse decorator parameters.
     */
    private parseDecoratorParams(paramsStr: string): Record<string, string> {
        const params: Record<string, string> = {};

        const matches = paramsStr.matchAll(/(\w+)\s*=\s*(?:["']([^"']+)["']|(\w+))/g);
        for (const match of matches) {
            params[match[1]] = match[2] || match[3];
        }

        return params;
    }

    /**
     * Provide hover for @sovereign decorator.
     */
    private async provideSovereignHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken
    ): Promise<vscode.Hover> {
        const functionInfo = this.findSovereignFunction(document, position);

        // Get cost estimate
        let estimate: CostEstimate | undefined;
        try {
            estimate = await this.getCostEstimate(document.fileName, token);
        } catch (error) {
            this.log.debug('Failed to get cost estimate', { error });
        }

        // Build markdown content
        const md = new vscode.MarkdownString();
        md.isTrusted = true;
        md.supportHtml = true;

        // Header
        md.appendMarkdown(`### 🛡️ Aethelred Sovereign Function\n\n`);

        // Function info
        if (functionInfo) {
            md.appendMarkdown(`**Function:** \`${functionInfo.name}\`\n\n`);
        }

        // Hardware info
        const hardware = functionInfo?.hardware || configManager.getTargetHardware();
        md.appendMarkdown(`**Hardware Target:** ${this.formatHardware(hardware)}\n\n`);

        // Jurisdiction
        const jurisdiction = functionInfo?.jurisdiction || configManager.getJurisdiction();
        const jurisdictionInfo = configManager.getJurisdictionInfo(jurisdiction);
        md.appendMarkdown(`**Jurisdiction:** ${jurisdictionInfo.flag} ${jurisdictionInfo.name}\n\n`);

        // Compliance
        const regulations = functionInfo?.compliance || configManager.getRegulations();
        if (regulations.length > 0) {
            md.appendMarkdown(`**Compliance:** ${regulations.join(', ')}\n\n`);
        }

        // Separator
        md.appendMarkdown(`---\n\n`);

        // Cost estimate
        if (estimate) {
            md.appendMarkdown(`### 💰 Execution Estimate\n\n`);
            md.appendMarkdown(`| Metric | Value |\n`);
            md.appendMarkdown(`|--------|-------|\n`);
            md.appendMarkdown(`| **Cost** | \`${estimate.costAethel.toFixed(2)} AETHEL\` |\n`);
            md.appendMarkdown(`| **Power** | \`${estimate.powerWatts} W\` |\n`);
            md.appendMarkdown(`| **Time** | \`${estimate.executionTimeMs} ms\` |\n`);
            md.appendMarkdown(`| **Memory** | \`${estimate.memoryMb} MB\` |\n`);
            md.appendMarkdown(`| **TEE Overhead** | \`${estimate.teeOverheadPercent}%\` |\n\n`);
        } else {
            md.appendMarkdown(`*Cost estimate not available*\n\n`);
        }

        // Actions
        md.appendMarkdown(`---\n\n`);
        md.appendMarkdown(`[$(graph) View Report](command:aethelred.showComplianceReport) | `);
        md.appendMarkdown(`[$(verified) Generate Seal](command:aethelred.generateSeal) | `);
        md.appendMarkdown(`[$(book) Documentation](https://docs.aethelred.io/sovereign)\n`);

        return new vscode.Hover(md);
    }

    /**
     * Provide hover for sovereign function.
     */
    private async provideFunctionHover(
        functionInfo: SovereignFunctionInfo,
        token: vscode.CancellationToken
    ): Promise<vscode.Hover> {
        const md = new vscode.MarkdownString();
        md.isTrusted = true;

        md.appendMarkdown(`### 🔒 Sovereign Function: \`${functionInfo.name}\`\n\n`);

        if (functionInfo.hardware) {
            md.appendMarkdown(`**Hardware:** ${this.formatHardware(functionInfo.hardware)}\n\n`);
        }

        if (functionInfo.jurisdiction) {
            const info = configManager.getJurisdictionInfo(functionInfo.jurisdiction);
            md.appendMarkdown(`**Jurisdiction:** ${info.flag} ${info.name}\n\n`);
        }

        if (functionInfo.compliance?.length) {
            md.appendMarkdown(`**Compliance:** ${functionInfo.compliance.join(', ')}\n\n`);
        }

        md.appendMarkdown(`*Decorated at line ${functionInfo.decoratorLine}*\n`);

        return new vscode.Hover(md);
    }

    /**
     * Get cost estimate with caching.
     */
    private async getCostEstimate(
        filePath: string,
        token: vscode.CancellationToken
    ): Promise<CostEstimate | undefined> {
        // Check cache
        const cached = this.estimateCache.get(filePath);
        if (cached && Date.now() - cached.timestamp < this.cacheMaxAge) {
            return cached.estimate;
        }

        // Get from CLI
        const result = await aethelCli.estimateCost(filePath, undefined, {
            cancellation: token,
            timeout: 5000,
        });

        if (result.success && result.data) {
            this.estimateCache.set(filePath, {
                estimate: result.data,
                timestamp: Date.now(),
            });
            return result.data;
        }

        return undefined;
    }

    /**
     * Format hardware type for display.
     */
    private formatHardware(hardware: HardwareType | 'auto'): string {
        const icons: Record<string, string> = {
            'auto': '🔄 Auto-detect',
            'generic': '💻 Generic',
            'intel-sgx': '🔐 Intel SGX',
            'intel-sgx-dcap': '🔐 Intel SGX DCAP',
            'intel-tdx': '🔐 Intel TDX',
            'amd-sev': '🔐 AMD SEV',
            'amd-sev-snp': '🔐 AMD SEV-SNP',
            'arm-trustzone': '🔐 ARM TrustZone',
            'arm-cca': '🔐 ARM CCA',
            'aws-nitro': '☁️ AWS Nitro',
            'azure-confidential': '☁️ Azure Confidential',
            'gcp-confidential': '☁️ GCP Confidential',
            'nvidia-h100': '🎮 NVIDIA H100 CC',
            'nvidia-a100': '🎮 NVIDIA A100',
        };
        return icons[hardware] || hardware;
    }

    /**
     * Clear cache.
     */
    clearCache(): void {
        this.estimateCache.clear();
    }
}

/**
 * Register hover providers.
 */
export function registerHoverProviders(context: vscode.ExtensionContext): void {
    const provider = new AethelredHoverProvider();

    const languages = ['python', 'rust', 'typescript', 'javascript', 'helix'];

    for (const language of languages) {
        context.subscriptions.push(
            vscode.languages.registerHoverProvider({ language }, provider)
        );
    }
}
