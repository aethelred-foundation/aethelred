import * as vscode from 'vscode';

const COMMANDS = [
  'aethelred.submitJob',
  'aethelred.verifySeal',
  'aethelred.startDevnet',
  'aethelred.stopDevnet',
  'aethelred.showNodeStatus',
] as const;

function placeholderHandler(command: string) {
  return () =>
    vscode.window.showInformationMessage(
      `${command} is scaffolded in this repository, but the full VS Code workflow is not implemented here yet.`,
    );
}

export function activate(context: vscode.ExtensionContext): void {
  for (const command of COMMANDS) {
    context.subscriptions.push(vscode.commands.registerCommand(command, placeholderHandler(command)));
  }
}

export function deactivate(): void {}
