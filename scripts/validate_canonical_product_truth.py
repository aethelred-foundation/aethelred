#!/usr/bin/env python3
"""Validate that key external surfaces match the canonical product truth."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def load_truth(repo_root: Path) -> dict | None:
    path = repo_root / "docs" / "operations" / "CANONICAL_PRODUCT_TRUTH.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def read_text(repo_root: Path, rel_path: str) -> str:
    path = repo_root / rel_path
    if not path.exists():
        raise FileNotFoundError(f"missing required file: {rel_path}")
    return path.read_text(encoding="utf-8")


def ensure_path_exists(repo_root: Path, rel_path: str, label: str, errors: list[str]) -> Path | None:
    path = repo_root / rel_path
    if not path.exists():
        errors.append(f"{label}: missing referenced file: {rel_path}")
        return None
    return path


def validate_performance_claims(repo_root: Path, truth: dict, errors: list[str]) -> None:
    performance_claims = truth.get("performance_claims", {})
    register_path = performance_claims.get("register_path")
    if register_path:
        ensure_path_exists(repo_root, register_path, "performance_claims.register_path", errors)

    seen_ids: set[str] = set()
    for entry in performance_claims.get("entries", []):
        claim_id = entry.get("id", "<missing>")
        if claim_id in seen_ids:
            errors.append(f"performance_claims.entries: duplicate claim id {claim_id}")
        seen_ids.add(claim_id)

        status = entry.get("status")
        public_allowed = bool(entry.get("public_allowed"))
        internal_only = bool(entry.get("internal_planning_only"))

        if public_allowed and status != "VERIFIED":
            errors.append(
                f"performance_claims.entries[{claim_id}]: public_allowed=true requires VERIFIED status"
            )
        if internal_only and public_allowed:
            errors.append(
                f"performance_claims.entries[{claim_id}]: internal planning only claims cannot be public"
            )
        if "register_row" not in entry:
            errors.append(f"performance_claims.entries[{claim_id}]: missing register_row")
        if not entry.get("claim"):
            errors.append(f"performance_claims.entries[{claim_id}]: missing claim text")


def validate_token_state(truth: dict, errors: list[str]) -> None:
    token_state = truth.get("token_state", {})
    tokenomics = truth.get("tokenomics", {})
    canonical_supply = tokenomics.get("fixed_supply_aethel")

    if token_state.get("supply_model") != "fixed":
        errors.append("token_state.supply_model must be 'fixed'")
    if token_state.get("total_supply_aethel") != canonical_supply:
        errors.append("token_state.total_supply_aethel does not match tokenomics.fixed_supply_aethel")
    if token_state.get("max_supply_cap_aethel") != canonical_supply:
        errors.append("token_state.max_supply_cap_aethel does not match tokenomics.fixed_supply_aethel")
    if token_state.get("post_genesis_inflation") != "zero":
        errors.append("token_state.post_genesis_inflation must be 'zero'")
    if token_state.get("inflation_bps") != tokenomics.get("post_genesis_inflation_bps"):
        errors.append("token_state.inflation_bps does not match tokenomics.post_genesis_inflation_bps")


def validate_regulatory_state(repo_root: Path, truth: dict, errors: list[str]) -> None:
    regulatory_state = truth.get("regulatory_state", {})
    tracker_path = regulatory_state.get("filing_tracker")
    if not tracker_path:
        errors.append("regulatory_state.filing_tracker is required")
        return

    tracker = ensure_path_exists(repo_root, tracker_path, "regulatory_state.filing_tracker", errors)
    if tracker is None:
        return

    tracker_text = tracker.read_text(encoding="utf-8")
    current_status = regulatory_state.get("adgm_filing_status")
    if current_status and f"Current status: `{current_status}`" not in tracker_text:
        errors.append(
            f"regulatory_state.adgm_filing_status '{current_status}' does not match {tracker_path}"
        )

    if not regulatory_state.get("allowed_public_wording"):
        errors.append("regulatory_state.allowed_public_wording must not be empty")
    if not regulatory_state.get("prohibited_public_wording"):
        errors.append("regulatory_state.prohibited_public_wording must not be empty")

    if not regulatory_state.get("csp_appointed") and current_status not in {"SUBMISSION_PREPARATION"}:
        errors.append(
            "regulatory_state.csp_appointed is false but adgm_filing_status is beyond SUBMISSION_PREPARATION"
        )


def validate_counterparty_state(repo_root: Path, truth: dict, errors: list[str]) -> None:
    counterparty_state = truth.get("counterparty_disclosure_state", {})
    register_path = counterparty_state.get("register_path")
    if not register_path:
        errors.append("counterparty_disclosure_state.register_path is required")
        return

    register_file = ensure_path_exists(
        repo_root,
        register_path,
        "counterparty_disclosure_state.register_path",
        errors,
    )
    if register_file is None:
        return

    register = json.loads(register_file.read_text(encoding="utf-8"))
    if register.get("policy") != counterparty_state.get("policy"):
        errors.append("counterparty register policy does not match canonical truth")

    state_model = set(counterparty_state.get("state_model", []))
    public_names = set(counterparty_state.get("public_named_counterparties", []))
    allowed_public_names: set[str] = set()

    for entry in register.get("entries", []):
        state = entry.get("state")
        name = entry.get("name")
        if state not in state_model:
            errors.append(
                f"counterparty register entry '{name or '<missing>'}' has unknown state '{state}'"
            )
        if entry.get("public_name_allowed"):
            if state != "EXECUTED":
                errors.append(
                    f"counterparty register entry '{name or '<missing>'}' is public without EXECUTED state"
                )
            if name:
                allowed_public_names.add(name)

    if public_names != allowed_public_names:
        errors.append(
            "counterparty_disclosure_state.public_named_counterparties does not match EXECUTED public entries"
        )


def validate_demo_state(repo_root: Path, truth: dict, errors: list[str]) -> None:
    demo_state = truth.get("demo_state", {})
    evidence_path = demo_state.get("local_doctor_evidence")
    if evidence_path:
        ensure_path_exists(repo_root, evidence_path, "demo_state.local_doctor_evidence", errors)

    if demo_state.get("canonical_customer_demo_path") != "hosted_testnet_only":
        errors.append("demo_state.canonical_customer_demo_path must remain 'hosted_testnet_only'")


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    truth = load_truth(repo_root)
    if truth is None:
        print("canonical product truth skipped: docs/operations/CANONICAL_PRODUCT_TRUTH.json not present")
        return 0
    code_rules = truth.get("code_rules", {})
    rules = truth["surface_rules"]
    withdrawn_notice = truth["tokenomics"]["withdrawn_draft_notice"]
    errors: list[str] = []

    for rel_path, snippets in code_rules.get("required_snippets", {}).items():
        text = read_text(repo_root, rel_path)
        for snippet in snippets:
            if snippet not in text:
                errors.append(f"{rel_path}: missing required code snippet: {snippet}")

    for rel_path, patterns in code_rules.get("banned_patterns", {}).items():
        text = read_text(repo_root, rel_path)
        for pattern in patterns:
            if re.search(pattern, text):
                errors.append(f"{rel_path}: banned code pattern matched: {pattern}")

    for rel_path in rules["public_files"]:
        text = read_text(repo_root, rel_path)
        for pattern in rules["banned_patterns"]:
            if re.search(pattern, text):
                errors.append(f"{rel_path}: banned pattern matched: {pattern}")
        for snippet in rules["required_snippets"].get(rel_path, []):
            if snippet not in text:
                errors.append(f"{rel_path}: missing required snippet: {snippet}")

    for rel_path in rules["withdrawn_draft_files"]:
        text = read_text(repo_root, rel_path)
        if withdrawn_notice not in text:
            errors.append(f"{rel_path}: missing withdrawn draft notice")

    validate_performance_claims(repo_root, truth, errors)
    validate_token_state(truth, errors)
    validate_regulatory_state(repo_root, truth, errors)
    validate_counterparty_state(repo_root, truth, errors)
    validate_demo_state(repo_root, truth, errors)

    if errors:
        print("canonical product truth validation failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1

    print(
        "canonical product truth validated for "
        f"{len(code_rules.get('required_snippets', {}))} code surfaces, "
        f"{len(rules['public_files'])} public surfaces and "
        f"{len(rules['withdrawn_draft_files'])} withdrawn drafts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
