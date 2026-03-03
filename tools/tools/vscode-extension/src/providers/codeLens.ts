/**
 * Aethelred VS Code Extension - Code Lens Provider
 *
 * Provides inline code lens for sovereign functions showing
 * compliance status, cost estimates, and quick actions.
 */

import * as vscode from 'vscode';
import {
    SovereignFunctionInfo,
    CostEstimate,
    HardwareType,
    Jurisdiction,
} from '../types';
import { ComplianceLinter } from '../diagnostics/linter';
import { aethCli } from '../services/cli';
import { configManager } from '../utils/config';
import { logger, CategoryLogger } from '../utils/logger';

/**
 * Code lens data for a sovereign function.
 */
interface SovereignCodeLensData {
    functionInfo: SovereignFunctionInfo;
    hasViolations: boolean;
    violationCount: number;
    costEstimate?: CostEstimate;
}

/**
 * Code lens provider for Aethelred sovereign functions.
 */
export class AethelredCodeLensProvider implements vscode.CodeLensProvider {
    private readonly log: CategoryLogger;
    private readonly onDidChangeEmitter = new vscode.EventEmitter<void>();

    readonly onDidChangeCodeLenses = this.onDidChangeEmitter.event;

    constructor(private readonly linter: ComplianceLinter) {
        this.log = logger.createChild('CodeLens');

        // Refresh code lenses when violations change
        linter.onDidUpdateViolations(() => {
            this.onDidChangeEmitter.fire();
        });
    }

    /**
     * Provide code lenses for the document.
     */
    async provideCodeLenses(
        document: vscode.TextDocument,
        token: vscode.CancellationToken
    ): Promise<vscode.CodeLens[]> {
        if (!configManager.shouldShowCodeLens()) {
            return [];
        }

        const codeLenses: vscode.CodeLens[] = [];

        // Find all sovereign functions
        const functions = this.findSovereignFunctions(document);

        for (const func of functions) {
            if (token.isCancellationRequested) {
                break;
            }

            // Get violations for this function
            const violations = this.linter.getViolations(document.uri).filter(
                (v) => v.line >= func.decoratorLine && v.line <= func.endLine
            );

            const data: SovereignCodeLensData = {
                functionInfo: func,
                hasViolations: violations.length > 0,
                violationCount: violations.length,
            };

            // Create code lenses
            const range = new vscode.Range(
                func.decoratorLine - 1, 0,
                func.decoratorLine - 1, 0
            );

            // Status lens
            codeLenses.push(new vscode.CodeLens(range, {
                title: this.getStatusTitle(data),
                command: violations.length > 0
                    ? 'aethelred.showQuickFixes'
                    : 'aethelred.showComplianceReport',
                arguments: [document.uri, func],
                tooltip: this.getStatusTooltip(data),
            }));

            // Hardware lens
            const hardware = func.hardware || configManager.getTargetHardware();
            codeLenses.push(new vscode.CodeLens(range, {
                title: this.getHardwareTitle(hardware),
                command: 'aethelred.selectHardware',
                arguments: [document.uri, func],
                tooltip: `Target: ${hardware}`,
            }));

            // Jurisdiction lens
            const jurisdiction = func.jurisdiction || configManager.getJurisdiction();
            const jurisdictionInfo = configManager.getJurisdictionInfo(jurisdiction);
            codeLenses.push(new vscode.CodeLens(range, {
                title: `${jurisdictionInfo.flag} ${jurisdiction}`,
                command: 'aethelred.setJurisdiction',
                arguments: [document.uri, func],
                tooltip: `Jurisdiction: ${jurisdictionInfo.name}`,
            }));

            // Actions lens
            codeLenses.push(new vscode.CodeLens(range, {
                title: '$(verified) Seal',
                command: 'aethelred.generateSeal',
                arguments: [document.uri, func],
                tooltip: 'Generate Digital Seal',
            }));
        }

        return codeLenses;
    }

    /**
     * Resolve a code lens (add command if not present).
     */
    resolveCodeLens(
        codeLens: vscode.CodeLens,
        _token: vscode.CancellationToken
    ): vscode.ProviderResult<vscode.CodeLens> {
        return codeLens;
    }

    /**
     * Find all sovereign functions in a document.
     */
    private findSovereignFunctions(document: vscode.TextDocument): SovereignFunctionInfo[] {
        const functions: SovereignFunctionInfo[] = [];
        const text = document.getText();

        // Pattern for decorators
        const decoratorPattern = /@sovereign\s*(\([^)]*\))?|#\[sovereign\s*(\([^)]*\))?\]/g;

        let match;
        while ((match = decoratorPattern.exec(text)) !== null) {
            const decoratorStart = document.positionAt(match.index);
            const decoratorLine = decoratorStart.line;

            // Parse decorator parameters
            const paramsStr = match[1] || match[2] || '';
            const params = this.parseParams(paramsStr);

            // Find function definition after decorator
            const funcInfo = this.findFunctionAfterLine(document, decoratorLine);
            if (funcInfo) {
                functions.push({
                    ...funcInfo,
                    decoratorLine: decoratorLine + 1,
                    hardware: params.hardware as HardwareType | undefined,
                    jurisdiction: params.jurisdiction as Jurisdiction | undefined,
                    compliance: params.compliance?.split(',').map((s: string) => s.trim()),
                });
            }
        }

        return functions;
    }

    /**
     * Find function definition after a line.
     */
    private findFunctionAfterLine(
        document: vscode.TextDocument,
        startLine: number
    ): Partial<SovereignFunctionInfo> | null {
        for (let i = startLine; i < Math.min(document.lineCount, startLine + 5); i++) {
            const line = document.lineAt(i).text;

            // Python
            const pythonMatch = line.match(/def\s+(\w+)\s*\(/);
            if (pythonMatch) {
                return this.buildFunctionInfo(document, i, pythonMatch[1], pythonMatch.index || 0);
            }

            // Rust
            const rustMatch = line.match(/(?:pub\s+)?(?:async\s+)?fn\s+(\w+)/);
            if (rustMatch) {
                return this.buildFunctionInfo(document, i, rustMatch[1], rustMatch.index || 0);
            }

            // TypeScript/JavaScript
            const tsMatch = line.match(/(?:async\s+)?function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(/);
            if (tsMatch) {
                const name = tsMatch[1] || tsMatch[2];
                return this.buildFunctionInfo(document, i, name, tsMatch.index || 0);
            }
        }

        return null;
    }

    /**
     * Build function info object.
     */
    private buildFunctionInfo(
        document: vscode.TextDocument,
        line: number,
        name: string,
        column: number
    ): Partial<SovereignFunctionInfo> {
        // Find function end (simple heuristic)
        let endLine = line;
        let braceCount = 0;
        let started = false;

        for (let i = line; i < document.lineCount; i++) {
            const text = document.lineAt(i).text;
            for (const char of text) {
                if (char === '{' || char === ':') {
                    started = true;
                    if (char === '{') braceCount++;
                }
                if (char === '}') braceCount--;
            }

            if (started && braceCount <= 0) {
                endLine = i;
                break;
            }

            // Python-style end detection
            if (document.languageId === 'python' && i > line) {
                const currentIndent = text.match(/^\s*/)?.[0].length || 0;
                const startIndent = document.lineAt(line).text.match(/^\s*/)?.[0].length || 0;
                if (currentIndent <= startIndent && text.trim()) {
                    endLine = i - 1;
                    break;
                }
            }
        }

        return {
            name,
            file: document.fileName,
            line: line + 1,
            column: column + 1,
            endLine: endLine + 1,
            endColumn: document.lineAt(endLine).text.length + 1,
        };
    }

    /**
     * Parse decorator parameters.
     */
    private parseParams(paramsStr: string): Record<string, string> {
        const params: Record<string, string> = {};

        // Remove parentheses
        paramsStr = paramsStr.replace(/^\(|\)$/g, '');

        const matches = paramsStr.matchAll(/(\w+)\s*=\s*(?:["']([^"']+)["']|(\w+(?:\.\w+)*))/g);
        for (const match of matches) {
            params[match[1]] = match[2] || match[3];
        }

        return params;
    }

    /**
     * Get status title for code lens.
     */
    private getStatusTitle(data: SovereignCodeLensData): string {
        if (data.hasViolations) {
            const icon = data.violationCount > 2 ? '$(error)' : '$(warning)';
            return `${icon} ${data.violationCount} violation${data.violationCount === 1 ? '' : 's'}`;
        }
        return '$(check) Compliant';
    }

    /**
     * Get status tooltip.
     */
    private getStatusTooltip(data: SovereignCodeLensData): string {
        if (data.hasViolations) {
            return `${data.violationCount} compliance violation(s) detected. Click to view.`;
        }
        return 'Function is compliant with active regulations.';
    }

    /**
     * Get hardware title for code lens.
     */
    private getHardwareTitle(hardware: HardwareType | 'auto'): string {
        const icons: Record<string, string> = {
            'auto': '$(gear) Auto',
            'generic': '$(server) Generic',
            'intel-sgx': '$(lock) SGX',
            'intel-sgx-dcap': '$(lock) SGX-DCAP',
            'intel-tdx': '$(lock) TDX',
            'amd-sev': '$(lock) SEV',
            'amd-sev-snp': '$(lock) SEV-SNP',
            'aws-nitro': '$(cloud) Nitro',
            'azure-confidential': '$(cloud) Azure CC',
            'gcp-confidential': '$(cloud) GCP CC',
            'nvidia-h100': '$(circuit-board) H100',
        };
        return icons[hardware] || `$(server) ${hardware}`;
    }

    /**
     * Trigger refresh.
     */
    refresh(): void {
        this.onDidChangeEmitter.fire();
    }

    /**
     * Dispose resources.
     */
    dispose(): void {
        this.onDidChangeEmitter.dispose();
    }
}

/**
 * Register code lens providers.
 */
export function registerCodeLensProviders(
    context: vscode.ExtensionContext,
    linter: ComplianceLinter
): AethelredCodeLensProvider {
    const provider = new AethelredCodeLensProvider(linter);

    const languages = ['python', 'rust', 'typescript', 'javascript', 'helix'];

    for (const language of languages) {
        context.subscriptions.push(
            vscode.languages.registerCodeLensProvider({ language }, provider)
        );
    }

    return provider;
}
