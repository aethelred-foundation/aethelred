# Software Bill of Materials (SBOM)

Generated for the M42 pilot. Regenerate before each reviewed release tag.

| File | Scope | Format | How to regenerate |
|---|---|---|---|
| `npm-sdk.cyclonedx.json` | TypeScript SDK production deps (53 components) | **CycloneDX 1.x** | `cd sdk/typescript && npm sbom --sbom-format cyclonedx --omit dev` |
| `go-modules.json` | Go module graph (852 modules) | `go list -m -json all` | `go list -m -json all > go-modules.json` |

## License posture (npm SDK, from the CycloneDX SBOM)

| License | Components |
|---|---:|
| MIT | 51 |
| BSD‑3‑Clause | 1 |
| ISC | 1 |

**All permissive; no copyleft (GPL/AGPL/LGPL/SSPL/…) detected.**

## Pre‑diligence follow‑ups (tooling not installed in the generation environment)

- **CycloneDX Go SBOM:** `cyclonedx-gomod app -json -output go.cyclonedx.json ./cmd/...` (network fetch; run in CI).
- **Go license scan:** `go-licenses report ./...` (produces per‑module license + flags forbidden licenses).
- **Container image scan:** build the pilot images, then `grype <image>` or `trivy image <image>`; attach results here.
- **Signed artifacts:** sign the reviewed release tag and SBOMs (e.g. cosign) so M42 can verify provenance.
