# Helix DSL (`.helix`) Guide

Helix is Aethelred's domain-specific language for authoring **verifiable AI workflows** that can be compiled into deterministic execution artifacts and linked to PoUW verification.

Tooling-focused reference:
- `$AETHELRED_REPO_ROOT/docs/guides/helix-tooling.md`

## What A `.helix` File Is

- File extension: `.helix`
- Purpose: declare model logic + verification intent (proof + attestation constraints)
- Runtime role: source input to the Helix compiler in the Rust SDK module:
  - `$AETHELRED_REPO_ROOT/sdk/aethelred-sdk/src/helix/mod.rs`

## Integration Path In Aethelred

1. Author Helix source (`.helix`) in app repo.
2. Compile through `HelixCompiler` in the SDK.
3. Register compiled artifact/model metadata on-chain.
4. Submit jobs referencing the model ID/hash.
5. Verify outputs with seal + proof/attestation paths.

## Minimal Example

```helix
model credit_score_v1 {
  fn infer(input: tensor) -> tensor {
    let output = input;
    return output;
  }
}

proof {
  verify(model = "credit_score_v1", attestation = true, zkml = true);
}

seal {
  emit(output_hash = "0xabc123");
}
```

## Tooling Support

VS Code extension support now includes:

- Language ID: `helix`
- File association: `*.helix`
- Syntax grammar: `$AETHELRED_REPO_ROOT/vscode-extension/syntaxes/helix.tmLanguage.json`
- Language config: `$AETHELRED_REPO_ROOT/vscode-extension/language-configuration.json`
- Snippet pack: `$AETHELRED_REPO_ROOT/vscode-extension/snippets/helix.json`

## Current Maturity Notes

Helix compiler interfaces are present in the Rust SDK. Some internals are still intentionally minimal placeholders (tokenization/parsing/type-check scaffolding), so production pipelines should pin compiler behavior and validate generated artifacts in CI.
