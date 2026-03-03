# Helix Tooling Guide

This guide documents how `.helix` files integrate with Aethelred tooling.

## What Helix Is

- File extension: `.helix`
- Purpose: define deterministic AI workflow intent and verification requirements.
- Primary language spec: `docs/sdk/helix-dsl.md`

## Toolchain Integration

- Rust SDK compiler module:
  - `sdk/aethelred-sdk/src/helix/mod.rs`
- VS Code language grammar:
  - `vscode-extension/syntaxes/helix.tmLanguage.json`
- VS Code snippets:
  - `vscode-extension/snippets/helix.json`
- VS Code language registration:
  - `vscode-extension/package.json`

## Expected Developer Flow

1. Author `.helix` source in your app repo.
2. Compile/validate with the Helix SDK module.
3. Register resulting model/proof metadata on-chain.
4. Submit PoUW jobs against the registered model.
5. Verify output seals and attestations during result processing.

## Maturity Notes

- Syntax support and snippets are production-usable for authoring.
- Compiler interfaces are present and stable at API level.
- Advanced compiler internals should be pinned and validated in CI before mainnet release.
