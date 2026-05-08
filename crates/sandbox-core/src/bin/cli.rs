//! `aethelred-sandbox` — enterprise CLI for the Aethelred Infinity Sandbox.
//!
//! Subcommands:
//!
//!   keygen --out <KEY_FILE>                 Generate a hybrid keypair.
//!   sign --key <KEY_FILE> --in <SEAL.json>  Sign a seal, write SignedSeal.
//!   verify --pubkey <PUB_FILE> --in <SEAL>  Verify a SignedSeal.
//!   scan [--in <FILE>] [--text "..."]       Scan for sensitive data.
//!   audit --bundle <FILE> --format <fmt>    Render an audit trail.
//!   prometheus --bundle <FILE>              Emit Prometheus metrics for a bundle.
//!   schema [--feature]                      (Schema export — needs `--features schema`.)
//!
//! Flags:
//!
//!   --json                                  Emit JSON for machine parsing.
//!   --quiet                                 Suppress non-essential output.
//!
//! Exit codes:
//!
//!   0   ok
//!   1   verification failed / scan found sensitive data
//!   2   bad arguments / IO error
//!   3   crypto error
//!   4   unsupported / not yet implemented

#![allow(clippy::needless_lifetimes)]

use aethelred_sandbox_core::audit::{AuditFormat, AuditTrail};
use aethelred_sandbox_core::evidence::EvidenceBundle;
use aethelred_sandbox_core::scanner::Scanner;
use aethelred_sandbox_core::seal::DigitalSeal;
use std::io::Read;
use std::process::ExitCode;

#[cfg(feature = "real-crypto")]
use aethelred_core::crypto::hybrid::{HybridKeyPair, HybridPublicKey};
#[cfg(feature = "real-crypto")]
use aethelred_sandbox_core::crypto_signing::{HybridSealSigner, HybridSealVerifier, SealSigner, SignedSeal};

const USAGE: &str = "\
aethelred-sandbox - enterprise CLI

Usage:
  aethelred-sandbox <command> [args]

Commands:
  keygen     --out <PUB_FILE>
             Generate a hybrid (ECDSA + Dilithium-3) keypair and write
             only the PUBLIC key to <PUB_FILE>. The secret key is NOT
             persisted — production deployments back HybridSealSigner
             with an HSM (PKCS#11 / AWS KMS / Azure Key Vault / GCP KMS).

  sign       [--in <SEAL.json>] [--out <SIGNED.json>] [--pub-out <PUB.json>]
             [--signer-id <ID>]
             Sign a seal with a fresh in-memory hybrid signer. Reads the
             seal from --in or stdin; writes the signed seal to --out or
             stdout. If --pub-out is given, also writes the matching
             public key (use this for end-to-end shell verify).

  verify     --pubkey <PUB_FILE> --in <SIGNED.json> [--signer-id <ID>] [--strict-mainnet]
             Verify a SignedSeal against a public key. Exit 0 if valid.

  scan       [--in <FILE>] [--text \"...\"] [--json]
             Scan for sensitive data (PII / PHI / PCI / classification).
             Exit 0 if no findings, 1 otherwise.

  audit      --bundle <FILE> [--format plain|markdown|csv|json]
             Render an audit trail from an evidence bundle.

  prometheus --bundle <FILE>
             Emit Prometheus-format metrics for a bundle.

  help                                Print this help.

Exit codes:
  0 ok | 1 finding/verify failed | 2 bad args/io | 3 crypto | 4 unsupported
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    match args[0].as_str() {
        "keygen" => cmd_keygen(&args[1..]),
        "sign" => cmd_sign(&args[1..]),
        "verify" => cmd_verify(&args[1..]),
        "scan" => cmd_scan(&args[1..]),
        "audit" => cmd_audit(&args[1..]),
        "prometheus" => cmd_prometheus(&args[1..]),
        "help" | "-h" | "--help" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        "version" | "-V" | "--version" => {
            println!("aethelred-sandbox {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("error: unknown command: {other}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

// =============================================================================
// Argument parsing helpers
// =============================================================================

fn parse_flag(args: &[String], name: &str) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if i + 1 < args.len() {
                return Some(args[i + 1].clone());
            }
            return None;
        }
        i += 1;
    }
    None
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn read_input(path: Option<&str>) -> Result<Vec<u8>, String> {
    match path {
        Some(p) => std::fs::read(p).map_err(|e| format!("read {}: {}", p, e)),
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("read stdin: {e}"))?;
            Ok(buf)
        }
    }
}

fn write_output(path: Option<&str>, bytes: &[u8]) -> Result<(), String> {
    match path {
        Some(p) => std::fs::write(p, bytes).map_err(|e| format!("write {}: {}", p, e)),
        None => {
            use std::io::Write;
            std::io::stdout()
                .write_all(bytes)
                .map_err(|e| format!("write stdout: {e}"))
        }
    }
}

// =============================================================================
// keygen
// =============================================================================

#[cfg(feature = "real-crypto")]
fn cmd_keygen(args: &[String]) -> ExitCode {
    let out = match parse_flag(args, "--out") {
        Some(v) => v,
        None => {
            eprintln!("error: keygen requires --out <PUB_FILE>");
            return ExitCode::from(2);
        }
    };
    // We deliberately do NOT serialise secret-key bytes from the CLI.
    // Production deployments must back the signer with an HSM
    // (PKCS#11 / AWS KMS / Azure Key Vault / GCP KMS / CloudHSM).
    // The CLI generates a fresh keypair, writes only the *public* key,
    // and keeps the secret in-process. For end-to-end sign+verify in
    // shell scripts, use:
    //
    //   aethelred-sandbox sign --in seal.json --pub-out pub.json --out signed.json
    //
    // which writes both the signed seal and its matching public-key
    // bundle in one call.
    let kp = match HybridKeyPair::generate() {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("crypto error: {e}");
            return ExitCode::from(3);
        }
    };
    let bundle = serde_json::json!({
        "schema_version": 1,
        "algorithm": "hybrid-ecdsa-dilithium3",
        "public_bytes_hex": hex::encode(kp.public_key().to_bytes()),
        "secret_storage": "in_memory_only_use_hsm_in_prod",
        "generated_at": time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    });
    let pretty = match serde_json::to_string_pretty(&bundle) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("serialise: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = std::fs::write(&out, pretty.as_bytes()) {
        eprintln!("write {}: {}", out, e);
        return ExitCode::from(2);
    }
    if !has_flag(args, "--quiet") {
        eprintln!(
            "wrote PUBLIC key to {} (algorithm: hybrid-ecdsa-dilithium3).\n\
             secret key was NOT persisted; use HSM-backed signers in production.",
            out
        );
    }
    ExitCode::SUCCESS
}

#[cfg(not(feature = "real-crypto"))]
fn cmd_keygen(_args: &[String]) -> ExitCode {
    eprintln!("error: keygen requires the `real-crypto` feature");
    ExitCode::from(4)
}

// =============================================================================
// sign
// =============================================================================

#[cfg(feature = "real-crypto")]
fn cmd_sign(args: &[String]) -> ExitCode {
    let in_path = parse_flag(args, "--in");
    let out_path = parse_flag(args, "--out");
    let pub_out = parse_flag(args, "--pub-out");
    let signer_id = parse_flag(args, "--signer-id").unwrap_or_else(|| "cli-signer".into());

    // Generate a fresh in-memory signer. For production, swap this for
    // an HSM-backed signer (`aethelred_core::crypto::signer::ValidatorHsmSigner`).
    let signer = match HybridSealSigner::generate(&signer_id) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("crypto: {e}");
            return ExitCode::from(3);
        }
    };

    let bytes = match read_input(in_path.as_deref()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("io: {e}");
            return ExitCode::from(2);
        }
    };
    let seal: DigitalSeal = match serde_json::from_slice(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("parse seal: {e}");
            return ExitCode::from(2);
        }
    };
    let signed = match signer.sign_seal(seal) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sign: {e}");
            return ExitCode::from(3);
        }
    };
    let pretty = match serde_json::to_string_pretty(&signed) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("serialise: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = write_output(out_path.as_deref(), pretty.as_bytes()) {
        eprintln!("io: {e}");
        return ExitCode::from(2);
    }
    if let Some(pub_path) = pub_out {
        let pub_bundle = serde_json::json!({
            "schema_version": 1,
            "algorithm": "hybrid-ecdsa-dilithium3",
            "signer_id": signer_id,
            "public_bytes_hex": hex::encode(signer.public_key().to_bytes()),
        });
        match serde_json::to_string_pretty(&pub_bundle) {
            Ok(s) => {
                if let Err(e) = std::fs::write(&pub_path, s.as_bytes()) {
                    eprintln!("write pubkey {}: {}", pub_path, e);
                    return ExitCode::from(2);
                }
            }
            Err(e) => {
                eprintln!("serialise pubkey: {e}");
                return ExitCode::from(2);
            }
        }
    }
    if !has_flag(args, "--quiet") {
        let pubkey_hex = hex::encode(signer.public_key().to_bytes());
        eprintln!(
            "signed by {} (pubkey: {}…)",
            signer_id,
            &pubkey_hex[..32.min(pubkey_hex.len())]
        );
    }
    ExitCode::SUCCESS
}

#[cfg(not(feature = "real-crypto"))]
fn cmd_sign(_args: &[String]) -> ExitCode {
    eprintln!("error: sign requires the `real-crypto` feature");
    ExitCode::from(4)
}

// =============================================================================
// verify
// =============================================================================

#[cfg(feature = "real-crypto")]
fn cmd_verify(args: &[String]) -> ExitCode {
    let pub_path = match parse_flag(args, "--pubkey") {
        Some(v) => v,
        None => {
            eprintln!("error: verify requires --pubkey <PUB_FILE>");
            return ExitCode::from(2);
        }
    };
    let in_path = parse_flag(args, "--in");
    let signer_id = parse_flag(args, "--signer-id").unwrap_or_else(|| "cli-signer".into());

    // Load the public key.
    let pubkey_bundle: serde_json::Value = match std::fs::read_to_string(&pub_path)
        .map_err(|e| format!("read {}: {}", pub_path, e))
        .and_then(|s| serde_json::from_str(&s).map_err(|e| format!("parse: {e}")))
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("pubkey: {e}");
            return ExitCode::from(2);
        }
    };
    let pub_hex = match pubkey_bundle.get("public_bytes_hex").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => {
            eprintln!("pubkey file: missing 'public_bytes_hex'");
            return ExitCode::from(2);
        }
    };
    let pub_bytes = match hex::decode(&pub_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("pubkey hex: {e}");
            return ExitCode::from(2);
        }
    };
    let pubkey = match HybridPublicKey::from_bytes(&pub_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pubkey decode: {e}");
            return ExitCode::from(3);
        }
    };

    // Load the signed seal.
    let bytes = match read_input(in_path.as_deref()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("io: {e}");
            return ExitCode::from(2);
        }
    };
    let signed: SignedSeal = match serde_json::from_slice(&bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("parse signed seal: {e}");
            return ExitCode::from(2);
        }
    };

    let mut verifier = if has_flag(args, "--strict-mainnet") {
        HybridSealVerifier::strict_mainnet()
    } else {
        HybridSealVerifier::empty()
    };
    verifier.register(signer_id, pubkey);

    match verifier.verify_signed_seal(&signed) {
        Ok(_) => {
            if !has_flag(args, "--quiet") {
                println!("verify: OK ({})", signed.envelope.algorithm);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("verify failed: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(not(feature = "real-crypto"))]
fn cmd_verify(_args: &[String]) -> ExitCode {
    eprintln!("error: verify requires the `real-crypto` feature");
    ExitCode::from(4)
}

// =============================================================================
// scan
// =============================================================================

fn cmd_scan(args: &[String]) -> ExitCode {
    let in_path = parse_flag(args, "--in");
    let inline_text = parse_flag(args, "--text");
    let json_out = has_flag(args, "--json");
    let text = if let Some(t) = inline_text {
        t
    } else {
        match read_input(in_path.as_deref()) {
            Ok(b) => match String::from_utf8(b) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("input is not utf-8: {e}");
                    return ExitCode::from(2);
                }
            },
            Err(e) => {
                eprintln!("io: {e}");
                return ExitCode::from(2);
            }
        }
    };
    let scanner = Scanner::new();
    let findings = scanner.scan(&text);
    let summary = scanner.summary(&text);
    if json_out {
        let bundle = serde_json::json!({
            "summary": summary,
            "findings": findings,
        });
        match serde_json::to_string_pretty(&bundle) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("serialise: {e}");
                return ExitCode::from(2);
            }
        }
    } else if findings.is_empty() {
        if !has_flag(args, "--quiet") {
            println!("scan: no findings");
        }
    } else {
        for f in &findings {
            println!(
                "{} [{}] @ {}-{} confidence={} ctx={}",
                f.detector, summary_class(&f.class), f.start, f.end, f.confidence, f.redacted_context
            );
        }
        eprintln!(
            "scan: {} findings (pii={} phi={} pci={} classified={} secret={})",
            summary.total, summary.pii, summary.phi, summary.pci, summary.classified, summary.secret
        );
    }
    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn summary_class(c: &aethelred_sandbox_core::scanner::SensitiveClass) -> &'static str {
    use aethelred_sandbox_core::scanner::SensitiveClass::*;
    match c {
        Pii => "PII",
        Phi => "PHI",
        Pci => "PCI",
        Classified => "CLASSIFIED",
        Secret => "SECRET",
    }
}

// =============================================================================
// audit
// =============================================================================

fn cmd_audit(args: &[String]) -> ExitCode {
    let bundle_path = match parse_flag(args, "--bundle") {
        Some(v) => v,
        None => {
            eprintln!("error: audit requires --bundle <FILE>");
            return ExitCode::from(2);
        }
    };
    let bytes = match std::fs::read(&bundle_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {}: {}", bundle_path, e);
            return ExitCode::from(2);
        }
    };
    let bundle: EvidenceBundle = match serde_json::from_slice(&bytes) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("parse: {e}");
            return ExitCode::from(2);
        }
    };
    let trail = AuditTrail::from_bundle(&bundle);
    let format = parse_flag(args, "--format")
        .unwrap_or_else(|| "markdown".into())
        .to_lowercase();
    let out = match format.as_str() {
        "plain" | "plaintext" | "text" => trail.render(AuditFormat::PlainText),
        "markdown" | "md" => trail.render(AuditFormat::Markdown),
        "csv" => trail.render(AuditFormat::Csv),
        "json" => match serde_json::to_string_pretty(&trail) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("serialise: {e}");
                return ExitCode::from(2);
            }
        },
        other => {
            eprintln!("unsupported --format: {other} (use plain|markdown|csv|json)");
            return ExitCode::from(2);
        }
    };
    println!("{out}");
    ExitCode::SUCCESS
}

// =============================================================================
// prometheus
// =============================================================================

fn cmd_prometheus(args: &[String]) -> ExitCode {
    let bundle_path = match parse_flag(args, "--bundle") {
        Some(v) => v,
        None => {
            eprintln!("error: prometheus requires --bundle <FILE>");
            return ExitCode::from(2);
        }
    };
    let bytes = match std::fs::read(&bundle_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {}: {}", bundle_path, e);
            return ExitCode::from(2);
        }
    };
    let bundle: EvidenceBundle = match serde_json::from_slice(&bytes) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("parse: {e}");
            return ExitCode::from(2);
        }
    };
    use aethelred_sandbox_core::metrics::{MetricsRecorder, SandboxMetrics};
    let m = SandboxMetrics::new();
    for entry in &bundle.entries {
        let sector = format!("{:?}", entry.seal.sector).to_lowercase();
        m.record_seal(&sector, &entry.seal.workflow_id, "sealed");
    }
    m.set_evidence_log_size(&bundle.tenant_id, bytes.len() as u64);
    println!("{}", m.export_prometheus());
    ExitCode::SUCCESS
}
