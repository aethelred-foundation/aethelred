import * as vscode from 'vscode';
import {
    formatStatusBarText,
    iconNameForJobStatus,
    localTestnetUpCommand,
    NETWORKS,
    verifySealJsonPayload,
} from './helpers.mjs';

let statusBarItem: vscode.StatusBarItem;
let sealDiagnostics: vscode.DiagnosticCollection;

export function activate(context: vscode.ExtensionContext) {
    console.log('Aethelred extension activated');

    // Status bar
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.text = formatStatusBarText('Testnet');
    statusBarItem.tooltip = 'Click to change network';
    statusBarItem.command = 'aethelred.connect';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    sealDiagnostics = vscode.languages.createDiagnosticCollection('aethelred-seals');
    context.subscriptions.push(sealDiagnostics);

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('aethelred.connect', async () => {
            const network = await vscode.window.showQuickPick(
                [...NETWORKS],
                { placeHolder: 'Select network' }
            );
            if (network) {
                statusBarItem.text = formatStatusBarText(network);
                vscode.window.showInformationMessage(`Connected to ${network}`);
            }
        }),

        vscode.commands.registerCommand('aethelred.submitJob', async () => {
            const modelHash = await vscode.window.showInputBox({
                prompt: 'Enter model hash',
                placeHolder: '0x...'
            });
            if (!modelHash) return;

            const inputHash = await vscode.window.showInputBox({
                prompt: 'Enter input data hash',
                placeHolder: '0x...'
            });
            if (!inputHash) return;

            vscode.window.showInformationMessage('Job submitted successfully!');
        }),

        vscode.commands.registerCommand('aethelred.verifySeal', async () => {
            const sealId = await vscode.window.showInputBox({
                prompt: 'Enter seal ID',
                placeHolder: 'seal_...'
            });
            if (sealId) {
                vscode.window.showInformationMessage(`Use "Aethelred: Verify Seal In Editor" for offline inline verification. Seal lookup by ID can be wired to your RPC endpoint next.`);
            }
        }),

        vscode.commands.registerCommand('aethelred.verifySealInEditor', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('Open a JSON seal file (or select JSON text) first.');
                return;
            }

            const selectionText = editor.document.getText(editor.selection);
            const raw = selectionText.trim().length > 0 ? selectionText : editor.document.getText();
            if (!raw.trim()) {
                vscode.window.showWarningMessage('Editor is empty.');
                return;
            }

            try {
                const result = verifySealJsonPayload(raw);
                const docUri = editor.document.uri;
                const diagnostics: vscode.Diagnostic[] = [];
                const firstLine = new vscode.Range(0, 0, 0, Math.max(1, editor.document.lineAt(0).text.length));

                for (const err of result.errors) {
                    diagnostics.push(new vscode.Diagnostic(firstLine, err.message, vscode.DiagnosticSeverity.Error));
                }
                for (const warn of result.warnings) {
                    diagnostics.push(new vscode.Diagnostic(firstLine, warn.message, vscode.DiagnosticSeverity.Warning));
                }

                sealDiagnostics.set(docUri, diagnostics);

                const summary = `${result.valid ? 'Verified' : 'Failed'} | score=${result.score} | validators=${result.validatorCount}`;
                if (result.valid) {
                    await vscode.window.showInformationMessage(`${summary} | ${result.fingerprintSha256}`);
                } else {
                    await vscode.window.showErrorMessage(`${summary} | ${result.fingerprintSha256}`);
                }
            } catch (err) {
                await vscode.window.showErrorMessage(`Seal verification failed: ${(err as Error).message}`);
            }
        }),

        vscode.commands.registerCommand('aethelred.registerModel', async () => {
            const name = await vscode.window.showInputBox({
                prompt: 'Enter model name'
            });
            if (name) {
                vscode.window.showInformationMessage(`Model "${name}" registered!`);
            }
        }),

        vscode.commands.registerCommand('aethelred.startTestnet', () => {
            (async () => {
                const profile = await vscode.window.showQuickPick(
                    [
                        { label: 'mock', description: 'Fast startup using deterministic mock RPC (recommended for SDK/UI work)' },
                        { label: 'real-node', description: 'Run a validator-backed local RPC for deeper protocol integration checks' },
                    ],
                    { placeHolder: 'Select local testnet profile' }
                );
                if (!profile) {
                    return;
                }
                const terminal = vscode.window.createTerminal('Aethelred Testnet');
                terminal.sendText(localTestnetUpCommand(profile.label));
                terminal.show();
            })();
        }),

        vscode.commands.registerCommand('aethelred.openExplorer', () => {
            vscode.env.openExternal(vscode.Uri.parse('http://localhost:3000'));
        }),

        vscode.commands.registerCommand('aethelred.openDeveloperDashboard', () => {
            vscode.env.openExternal(vscode.Uri.parse('http://localhost:3101/devtools'));
        })
    );

    // Create tree view providers
    const networkProvider = new NetworkTreeProvider();
    vscode.window.registerTreeDataProvider('aethelred.network', networkProvider);

    const jobsProvider = new JobsTreeProvider();
    vscode.window.registerTreeDataProvider('aethelred.jobs', jobsProvider);

    // Lightweight completion provider for seal JSON authoring.
    context.subscriptions.push(
        vscode.languages.registerCompletionItemProvider(
            [{ language: 'json' }, { language: 'jsonc' }],
            {
                provideCompletionItems(document, position) {
                    const linePrefix = document.lineAt(position).text.slice(0, position.character);
                    if (!linePrefix.includes('"') && !linePrefix.trim().startsWith('{')) {
                        return [];
                    }
                    const fields = [
                        ['id', '"seal_..."'],
                        ['jobId', '"job_..."'],
                        ['modelHash', '"0x..."'],
                        ['inputCommitment', '"0x..."'],
                        ['outputCommitment', '"0x..."'],
                        ['status', '"SEAL_STATUS_ACTIVE"'],
                        ['requester', '"aethel1..."'],
                        ['createdAt', `"${new Date().toISOString()}"`],
                        ['validators', '[]'],
                        ['teeAttestation', '{}'],
                        ['consensus', '{}'],
                    ];
                    return fields.map(([field, sample]) => {
                        const item = new vscode.CompletionItem(field, vscode.CompletionItemKind.Field);
                        item.insertText = new vscode.SnippetString(`"${field}": ${sample}`);
                        item.detail = 'Aethelred Digital Seal field';
                        return item;
                    });
                }
            },
            '"'
        )
    );
}

class NetworkTreeProvider implements vscode.TreeDataProvider<NetworkItem> {
    getTreeItem(element: NetworkItem): vscode.TreeItem {
        return element;
    }

    getChildren(): NetworkItem[] {
        return [
            new NetworkItem('Status', 'Connected', vscode.TreeItemCollapsibleState.None),
            new NetworkItem('Network', 'Testnet', vscode.TreeItemCollapsibleState.None),
            new NetworkItem('Chain ID', 'aethelred-testnet-1', vscode.TreeItemCollapsibleState.None),
            new NetworkItem('Latest Block', '1,234,567', vscode.TreeItemCollapsibleState.None),
        ];
    }
}

class NetworkItem extends vscode.TreeItem {
    constructor(label: string, value: string, collapsibleState: vscode.TreeItemCollapsibleState) {
        super(`${label}: ${value}`, collapsibleState);
    }
}

class JobsTreeProvider implements vscode.TreeDataProvider<JobItem> {
    getTreeItem(element: JobItem): vscode.TreeItem {
        return element;
    }

    getChildren(): JobItem[] {
        return [
            new JobItem('job_abc123', 'Completed'),
            new JobItem('job_def456', 'Pending'),
            new JobItem('job_ghi789', 'Computing'),
        ];
    }
}

class JobItem extends vscode.TreeItem {
    constructor(jobId: string, status: string) {
        super(jobId, vscode.TreeItemCollapsibleState.None);
        this.description = status;
        this.iconPath = new vscode.ThemeIcon(iconNameForJobStatus(status));
    }
}

export function deactivate() {
    if (statusBarItem) {
        statusBarItem.dispose();
    }
    if (sealDiagnostics) {
        sealDiagnostics.dispose();
    }
}
