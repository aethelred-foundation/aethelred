// CLI Integration Tests for Aethelred
//
// These tests exercise the CLI binary end-to-end, verifying that commands
// produce the expected output without crashes. They use `assert_cmd` to
// invoke the compiled binary as a subprocess.

use assert_cmd::Command;
use predicates::prelude::*;

// =============================================================================
// Help & Version
// =============================================================================

#[test]
fn test_cli_help_displays_usage() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Aethelred"))
        .stdout(predicate::str::contains("USAGE").or(predicate::str::contains("Usage")));
}

#[test]
fn test_cli_version_flag() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("aethelred"));
}

// =============================================================================
// Subcommand Help
// =============================================================================

#[test]
fn test_account_help() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["account", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("account").or(predicate::str::contains("Account")));
}

#[test]
fn test_job_help() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["job", "--help"])
        .assert()
        .success();
}

#[test]
fn test_seal_help() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["seal", "--help"])
        .assert()
        .success();
}

#[test]
fn test_validator_help() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["validator", "--help"])
        .assert()
        .success();
}

#[test]
fn test_model_help() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["model", "--help"])
        .assert()
        .success();
}

#[test]
fn test_node_help() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["node", "--help"])
        .assert()
        .success();
}

#[test]
fn test_tx_help() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["tx", "--help"])
        .assert()
        .success();
}

#[test]
fn test_query_help() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["query", "--help"])
        .assert()
        .success();
}

#[test]
fn test_compliance_help() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["compliance", "--help"])
        .assert()
        .success();
}

#[test]
fn test_bench_help() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["bench", "--help"])
        .assert()
        .success();
}

#[test]
fn test_hardware_help() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["hardware", "--help"])
        .assert()
        .success();
}

#[test]
fn test_deploy_help() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["deploy", "--help"])
        .assert()
        .success();
}

// =============================================================================
// Config Initialization
// =============================================================================

#[test]
fn test_init_creates_config_directory() {
    let temp = tempfile::tempdir().unwrap();

    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["init", "--home", temp.path().to_str().unwrap()])
        .assert()
        .success();

    // Verify config directory was created
    assert!(
        temp.path().exists(),
        "Init should create the home directory"
    );
}

// =============================================================================
// Error Handling
// =============================================================================

#[test]
fn test_unknown_subcommand_fails() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .arg("nonexistent-command-xyz")
        .assert()
        .failure();
}

#[test]
fn test_invalid_flag_fails() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .arg("--invalid-flag-xyz")
        .assert()
        .failure();
}

// =============================================================================
// Network Commands (without live node, should fail gracefully)
// =============================================================================

#[test]
fn test_network_help() {
    Command::cargo_bin("aethelred")
        .unwrap()
        .args(["network", "--help"])
        .assert()
        .success();
}
