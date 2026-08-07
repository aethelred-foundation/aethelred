# vscode-aethelred

This directory is an internal scaffold for future VS Code developer tooling.

It is not a published extension package, and it should not be treated as a feature-complete developer product inside this repository snapshot.

## What Exists Today

- a minimal extension entrypoint that registers placeholder commands
- a basic `.aip` language scaffold
- package metadata and development scripts that now match the scaffolded state

## What Does Not Exist Yet

- a production-ready marketplace extension
- implemented job submission, seal verification, or live node management workflows
- an automated extension test suite

## Development

```bash
npm install
npm run compile
npm run lint
```

The current scripts validate the scaffold workspace only. Packaging and publishing are intentionally disabled here until the real extension implementation is added.
