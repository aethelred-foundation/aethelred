/**
 * Aethelred VS Code Extension - Code Actions
 *
 * Provides quick fixes and refactoring actions for compliance violations.
 * Integrates with the linter to offer automated remediation.
 */

import * as vscode from 'vscode';
import {
    ComplianceViolation,
    ViolationFix,
    AethelredDiagnostic,
} from '../types';
import { ComplianceLinter } from './linter';
import { logger, CategoryLogger } from '../utils/logger';

/**
 * Code action kinds provided by this extension.
 */
const AETHELRED_FIX = vscode.CodeActionKind.QuickFix.append('aethelred');
const AETHELRED_REFACTOR = vscode.CodeActionKind.Refactor.append('aethelred');

/**
 * Code action provider for Aethelred compliance fixes.
 */
export class AethelredCodeActionProvider implements vscode.CodeActionProvider {
    private readonly log: CategoryLogger;

    static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix,
        AETHELRED_FIX,
        AETHELRED_REFACTOR,
    ];

    static readonly metadata: vscode.CodeActionProviderMetadata = {
        providedCodeActionKinds: AethelredCodeActionProvider.providedCodeActionKinds,
    };

    constructor(private readonly linter: ComplianceLinter) {
        this.log = logger.createChild('CodeActions');
    }

    /**
     * Provide code actions for the given document and range.
     */
    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        _token: vscode.CancellationToken
    ): vscode.ProviderResult<(vscode.CodeAction | vscode.Command)[]> {
        const actions: vscode.CodeAction[] = [];

        // Get Aethelred diagnostics in the range
        const diagnostics = context.diagnostics.filter(
            (d) => d.source === 'Aethelred'
        ) as AethelredDiagnostic[];

        if (diagnostics.length === 0) {
            return actions;
        }

        // Generate actions for each diagnostic
        for (const diagnostic of diagnostics) {
            const violation = diagnostic.violation;
            const fixes = diagnostic.fixes ?? [];

            // Add quick fixes
            for (const fix of fixes) {
                const action = this.createQuickFixAction(document, diagnostic, fix);
                if (action) {
                    actions.push(action);
                }
            }

            // Add "Explain Violation" action
            if (violation) {
                actions.push(this.createExplainAction(violation));
            }

            // Add "Suppress Violation" action
            if (violation) {
                actions.push(this.createSuppressAction(document, diagnostic, violation));
            }

            // Add "Show Documentation" action
            if (diagnostic.code && typeof diagnostic.code === 'object') {
                actions.push(this.createDocumentationAction(diagnostic.code.target));
            }
        }

        // Add "Fix All" action if multiple violations
        if (diagnostics.length > 1) {
            const fixableCount = diagnostics.filter((d) => d.fixes?.length).length;
            if (fixableCount > 1) {
                actions.push(this.createFixAllAction(document, diagnostics));
            }
        }

        return actions;
    }

    /**
     * Create a quick fix action from a ViolationFix.
     */
    private createQuickFixAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        fix: ViolationFix
    ): vscode.CodeAction | undefined {
        if (!fix.replacement && (!fix.edits || fix.edits.length === 0)) {
            return undefined;
        }

        const action = new vscode.CodeAction(
            fix.title,
            fix.isPreferred ? vscode.CodeActionKind.QuickFix : AETHELRED_FIX
        );

        action.diagnostics = [diagnostic];
        action.isPreferred = fix.isPreferred;

        // Create workspace edit
        const edit = new vscode.WorkspaceEdit();

        if (fix.replacement !== undefined) {
            // Simple replacement
            edit.replace(document.uri, diagnostic.range, fix.replacement);
        } else if (fix.edits) {
            // Multiple edits
            for (const e of fix.edits) {
                const range = new vscode.Range(
                    e.range.start.line - 1,
                    e.range.start.column - 1,
                    e.range.end.line - 1,
                    e.range.end.column - 1
                );
                edit.replace(document.uri, range, e.newText);
            }
        }

        action.edit = edit;

        // Add commands
        if (fix.commands) {
            action.command = {
                title: 'Run Fix Commands',
                command: 'aethelred.runFixCommands',
                arguments: [fix.commands],
            };
        }

        return action;
    }

    /**
     * Create "Explain Violation" action.
     */
    private createExplainAction(violation: ComplianceViolation): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Explain This Violation',
            vscode.CodeActionKind.Empty
        );

        action.command = {
            title: 'Explain Violation',
            command: 'aethelred.explainViolation',
            arguments: [violation],
        };

        return action;
    }

    /**
     * Create "Suppress Violation" action.
     */
    private createSuppressAction(
        document: vscode.TextDocument,
        diagnostic: vscode.Diagnostic,
        violation: ComplianceViolation
    ): vscode.CodeAction {
        const action = new vscode.CodeAction(
            `Suppress: ${violation.id}`,
            vscode.CodeActionKind.QuickFix
        );

        action.diagnostics = [diagnostic];

        // Insert suppression comment
        const edit = new vscode.WorkspaceEdit();
        const line = diagnostic.range.start.line;
        const indent = document.lineAt(line).text.match(/^\s*/)?.[0] ?? '';

        let comment: string;
        switch (document.languageId) {
            case 'python':
                comment = `${indent}# aethelred-ignore: ${violation.id}\n`;
                break;
            case 'rust':
                comment = `${indent}// aethelred-ignore: ${violation.id}\n`;
                break;
            case 'typescript':
            case 'javascript':
                comment = `${indent}// aethelred-ignore: ${violation.id}\n`;
                break;
            default:
                comment = `${indent}// aethelred-ignore: ${violation.id}\n`;
        }

        edit.insert(document.uri, new vscode.Position(line, 0), comment);
        action.edit = edit;

        return action;
    }

    /**
     * Create "Show Documentation" action.
     */
    private createDocumentationAction(uri: vscode.Uri): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Show Documentation',
            vscode.CodeActionKind.Empty
        );

        action.command = {
            title: 'Open Documentation',
            command: 'vscode.open',
            arguments: [uri],
        };

        return action;
    }

    /**
     * Create "Fix All" action.
     */
    private createFixAllAction(
        document: vscode.TextDocument,
        diagnostics: AethelredDiagnostic[]
    ): vscode.CodeAction {
        const action = new vscode.CodeAction(
            'Fix All Aethelred Violations',
            vscode.CodeActionKind.QuickFix
        );

        action.diagnostics = diagnostics;

        const edit = new vscode.WorkspaceEdit();

        // Apply preferred fixes
        for (const diagnostic of diagnostics) {
            const preferredFix = diagnostic.fixes?.find((f) => f.isPreferred);
            if (preferredFix?.replacement) {
                edit.replace(document.uri, diagnostic.range, preferredFix.replacement);
            }
        }

        action.edit = edit;
        action.isPreferred = false;

        return action;
    }
}

/**
 * Register code action providers.
 */
export function registerCodeActionProviders(
    context: vscode.ExtensionContext,
    linter: ComplianceLinter
): void {
    const provider = new AethelredCodeActionProvider(linter);

    const languages = ['python', 'rust', 'typescript', 'javascript', 'helix'];

    for (const language of languages) {
        context.subscriptions.push(
            vscode.languages.registerCodeActionsProvider(
                { language },
                provider,
                AethelredCodeActionProvider.metadata
            )
        );
    }
}
