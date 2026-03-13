#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional


ROOT = pathlib.Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "docs" / "governance" / "repo-authority-registry.json"


@dataclass
class RepoLocalPath:
    repo: str
    path: pathlib.Path


LOCAL_REPO_CANDIDATES: Dict[str, List[pathlib.Path]] = {
    "AethelredFoundation/aethelred": [
        ROOT,
    ],
}


def load_registry() -> dict:
    try:
        return json.loads(REGISTRY_PATH.read_text())
    except FileNotFoundError:
        fail(f"missing registry file: {REGISTRY_PATH}")
    except json.JSONDecodeError as e:
        fail(f"invalid JSON in registry: {e}")


def fail(msg: str) -> None:
    print(f"[repo-authority] ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


def warn(msg: str) -> None:
    print(f"[repo-authority] WARN: {msg}", file=sys.stderr)


def info(msg: str) -> None:
    print(f"[repo-authority] {msg}")


def find_local_repo(repo_id: str) -> Optional[pathlib.Path]:
    for candidate in LOCAL_REPO_CANDIDATES.get(repo_id, []):
        if candidate.exists():
            return candidate
    return None


def parse_go_module(go_mod_path: pathlib.Path) -> Optional[str]:
    try:
        text = go_mod_path.read_text()
    except FileNotFoundError:
        return None
    m = re.search(r"^module\s+(\S+)\s*$", text, re.MULTILINE)
    return m.group(1) if m else None


def load_repo_authority_manifest(repo_root: pathlib.Path) -> Optional[dict]:
    p = repo_root / "repo-authority.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError as e:
        fail(f"{p}: invalid JSON ({e})")


def validate_registry_semantics(registry: dict) -> None:
    repos = registry.get("repos", [])
    groups = {g["id"]: g for g in registry.get("authority_groups", [])}
    if not repos:
        fail("registry has no repos")

    seen = set()
    for r in repos:
        rid = r.get("repo")
        if not rid or "/" not in rid:
            fail(f"invalid repo identifier: {rid!r}")
        if rid in seen:
            fail(f"duplicate repo entry in registry: {rid}")
        seen.add(rid)

    for gid, group in groups.items():
        members = [r for r in repos if r.get("authority_group") == gid]
        canonical = [r for r in members if r.get("role") == "canonical-chain"]
        if group.get("canonical_repo"):
            if len(canonical) != 1:
                fail(f"group {gid} must have exactly one canonical-chain repo entry")
            if canonical[0]["repo"] != group["canonical_repo"]:
                fail(
                    f"group {gid} canonical repo mismatch: registry group says {group['canonical_repo']} "
                    f"but repo list canonical is {canonical[0]['repo']}"
                )

    go_claims: Dict[str, List[dict]] = {}
    for r in repos:
        for mod in r.get("declared_modules", {}).get("go", []):
            go_claims.setdefault(mod, []).append(r)

    for mod, claimants in go_claims.items():
        if len(claimants) <= 1:
            continue
        groups_involved = {c.get("authority_group") for c in claimants}
        if len(groups_involved) != 1:
            fail(f"go module {mod} duplicated across multiple authority groups: {sorted(groups_involved)}")
        gid = next(iter(groups_involved))
        group = groups.get(gid)
        if not group:
            fail(f"go module {mod} duplicated in unknown authority group {gid}")
        if not group.get("allow_duplicate_go_module_during_transition", False):
            fail(f"go module {mod} duplicated without transition allowance in group {gid}")
        canonical_repo = group.get("canonical_repo")
        if not canonical_repo:
            fail(f"go module {mod} duplicated but group {gid} has no canonical_repo")
        if canonical_repo not in [c["repo"] for c in claimants]:
            fail(f"go module {mod} duplicated but canonical repo {canonical_repo} is not a claimant")
        for c in claimants:
            if c["repo"] == canonical_repo:
                if not c.get("release_authority", False):
                    fail(f"canonical repo {canonical_repo} must have release_authority=true")
            else:
                if c.get("release_authority", True):
                    fail(f"duplicate transitional repo {c['repo']} must have release_authority=false")


def validate_local_chain_repos(registry: dict) -> None:
    repos = {r["repo"]: r for r in registry["repos"]}
    chain_repos = [r["repo"] for r in registry["repos"] if r.get("role") == "canonical-chain"]
    for repo_id in chain_repos:
        local = find_local_repo(repo_id)
        if not local:
            warn(f"local clone not found for {repo_id}; skipping local validation")
            continue
        manifest = load_repo_authority_manifest(local)
        if manifest is None:
            fail(f"{repo_id} missing repo-authority.json in {local}")
        if manifest.get("repo") != repo_id:
            fail(f"{repo_id} manifest repo mismatch in {local}: {manifest.get('repo')}")
        reg = repos[repo_id]
        if manifest.get("role") != reg.get("role"):
            fail(f"{repo_id} manifest role mismatch (manifest={manifest.get('role')} registry={reg.get('role')})")
        if bool(manifest.get("release_authority")) != bool(reg.get("release_authority")):
            fail(
                f"{repo_id} release_authority mismatch (manifest={manifest.get('release_authority')} "
                f"registry={reg.get('release_authority')})"
            )
        module = parse_go_module(local / "go.mod")
        expected_mods = reg.get("declared_modules", {}).get("go", [])
        if not module:
            fail(f"{repo_id} missing or unparsable go.mod in {local}")
        if expected_mods and module not in expected_mods:
            fail(f"{repo_id} go.mod module {module} not declared in registry {expected_mods}")
        manifest_mod = manifest.get("go_module")
        if manifest_mod and manifest_mod != module:
            fail(f"{repo_id} repo-authority.json go_module {manifest_mod} != go.mod module {module}")
        readme = (local / "README.md").read_text(errors="ignore")
        if not re.search(r"authority", readme, re.IGNORECASE):
            fail(f"{repo_id} README.md missing authority notice language")
        if not re.search(r"canonical", readme, re.IGNORECASE):
            fail(f"{repo_id} README.md should state canonical status explicitly")
        if not re.search(r"source of truth", readme, re.IGNORECASE):
            fail(f"{repo_id} README.md should mention source-of-truth status")
    info("local chain repo manifests and go.mod authority claims validated")


def main() -> None:
    registry = load_registry()
    validate_registry_semantics(registry)
    validate_local_chain_repos(registry)
    info("registry semantics validated")


if __name__ == "__main__":
    main()
