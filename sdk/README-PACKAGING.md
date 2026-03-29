# SDK Packaging Validation

## What each gate proves

The SDK packageability tests validate that each SDK can be **packaged into a distributable artifact** and **consumed as a dependency** in an isolated project. This is the strongest local validation possible without publishing to a registry.

| SDK        | What is tested                                                                                      |
|------------|-----------------------------------------------------------------------------------------------------|
| TypeScript | `npm pack` produces a tarball; a fresh consumer project can `npm install` and `require()` it        |
| Python     | `python -m build` produces a wheel + sdist; a fresh venv can `pip install` the wheel and import it  |
| Go         | `go mod verify`, `go vet ./...`, and `go test -short ./...` pass on the source tree                 |
| Rust       | `cargo package` produces a `.crate`; a fresh consumer project can depend on the extracted crate     |

## What it does NOT prove

- **npm/PyPI/crates.io/Go proxy install**: These tests never hit a package registry. A published version could still fail if registry metadata, authentication, or naming conflicts exist.
- **Cross-platform compatibility**: Local runs only cover the host OS/arch. CI runs the same tests across multiple OS and language version matrices.
- **Transitive dependency resolution from registry**: The Go test uses source-tree validation (`go mod verify` + `go vet`) rather than `go get` from a module proxy, since the module is not yet published.

## How to run locally

```bash
# Main packageability script (all SDKs, fast)
bash scripts/sdk-clean-install-test.sh

# Detailed test suite (all SDKs, with version matrix cross-check)
bash tests/sdk/clean-install-test.sh
```

## CI reference

The CI workflow (`.github/workflows/sdk-clean-install.yml`) runs the same packageability model across OS and language version matrices. Local scripts are kept in sync with CI to ensure consistent results.
