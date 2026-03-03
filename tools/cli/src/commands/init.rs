//! # Project Initialization Command - Enterprise-Grade Scaffolding
//!
//! The `aethel init` command provides professional project scaffolding for
//! Aethelred AI blockchain applications. It supports multiple industry templates
//! with pre-configured compliance, security, and infrastructure settings.
//!
//! ## Features
//!
//! - **Industry Templates**: Finance, Healthcare, Green-Energy, General
//! - **Language Support**: Python, TypeScript, Rust, Go
//! - **Compliance Pre-configuration**: GDPR, HIPAA, UAE Data Protection
//! - **TEE Integration**: Intel SGX, AMD SEV, AWS Nitro ready
//! - **CI/CD Templates**: GitHub Actions, GitLab CI, Docker

use crate::config::Config;
use crate::InitArgs;
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Select};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

// ============================================================================
// Industry Templates
// ============================================================================

/// Industry template types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndustryTemplate {
    /// General purpose AI/ML project
    General,
    /// Financial services (credit scoring, fraud detection, risk assessment)
    Finance,
    /// Healthcare (medical imaging, drug discovery, patient data)
    Healthcare,
    /// Green energy (carbon tracking, ESG compliance, sustainability)
    GreenEnergy,
    /// Minimal setup for quick prototyping
    Minimal,
}

impl IndustryTemplate {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::General => "🔷 General Purpose",
            Self::Finance => "🏦 Finance & Banking",
            Self::Healthcare => "🏥 Healthcare & Life Sciences",
            Self::GreenEnergy => "🌱 Green Energy & ESG",
            Self::Minimal => "⚡ Minimal (Quick Start)",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::General => "Standard AI/ML project with full SDK integration",
            Self::Finance => {
                "Credit scoring, fraud detection, risk assessment with UAE/GDPR compliance"
            }
            Self::Healthcare => "Medical AI with HIPAA compliance and PHI protection",
            Self::GreenEnergy => "Carbon tracking, ESG metrics, sustainability reporting",
            Self::Minimal => "Bare minimum setup for quick prototyping",
        }
    }

    pub fn default_regulations(&self) -> Vec<&'static str> {
        match self {
            Self::General => vec!["GDPR"],
            Self::Finance => vec!["GDPR", "UAE-DPL", "PCI-DSS", "SOX"],
            Self::Healthcare => vec!["HIPAA", "GDPR", "HITECH"],
            Self::GreenEnergy => vec!["GDPR", "EU-CSRD", "SEC-ESG"],
            Self::Minimal => vec![],
        }
    }

    pub fn default_jurisdictions(&self) -> Vec<&'static str> {
        match self {
            Self::General => vec!["EU", "US"],
            Self::Finance => vec!["UAE", "EU", "US", "SG"],
            Self::Healthcare => vec!["US", "EU"],
            Self::GreenEnergy => vec!["EU", "US", "UAE"],
            Self::Minimal => vec!["EU"],
        }
    }

    pub fn requires_tee(&self) -> bool {
        matches!(self, Self::Finance | Self::Healthcare)
    }
}

// ============================================================================
// Main Run Function
// ============================================================================

pub async fn run(args: InitArgs, config: &Config) -> anyhow::Result<()> {
    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════════════╗".cyan()
    );
    println!(
        "{}",
        "║           🚀 AETHELRED PROJECT INITIALIZER v2.0                    ║".cyan()
    );
    println!(
        "{}",
        "║          Enterprise-Grade AI Blockchain Scaffolding                ║".cyan()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════════════╝".cyan()
    );
    println!();

    // Gather project info interactively or from args
    let project_config = if args.yes {
        ProjectConfig {
            name: args.name.unwrap_or_else(|| "aethelred-project".to_string()),
            template: parse_template(&args.template),
            language: args.lang.clone(),
            directory: args.dir.unwrap_or_else(|| {
                PathBuf::from(args.name.as_deref().unwrap_or("aethelred-project"))
            }),
            enable_tee: true,
            enable_zkml: false,
            enable_cicd: true,
            network: config.network.clone(),
        }
    } else {
        gather_project_config(&args, config).await?
    };

    // Display configuration summary
    println!();
    println!("{}", "📋 Project Configuration".bold());
    println!("{}", "─".repeat(50));
    println!("  {} {}", "Name:".bold(), project_config.name.cyan());
    println!(
        "  {} {}",
        "Template:".bold(),
        project_config.template.display_name().cyan()
    );
    println!(
        "  {} {}",
        "Language:".bold(),
        project_config.language.to_uppercase().cyan()
    );
    println!(
        "  {} {}",
        "Directory:".bold(),
        project_config.directory.display().to_string().cyan()
    );
    println!(
        "  {} {}",
        "TEE Enabled:".bold(),
        if project_config.enable_tee {
            "Yes".green()
        } else {
            "No".yellow()
        }
    );
    println!(
        "  {} {}",
        "zkML Enabled:".bold(),
        if project_config.enable_zkml {
            "Yes".green()
        } else {
            "No".yellow()
        }
    );
    println!();

    // Confirm if not using --yes
    if !args.yes {
        let confirm = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Create project with these settings?")
            .default(true)
            .interact()?;

        if !confirm {
            println!("{} Project creation cancelled.", "ℹ️".cyan());
            return Ok(());
        }
    }

    // Create project
    create_project(&project_config).await?;

    // Display success message and next steps
    display_success(&project_config);

    Ok(())
}

// ============================================================================
// Configuration Gathering
// ============================================================================

struct ProjectConfig {
    name: String,
    template: IndustryTemplate,
    language: String,
    directory: PathBuf,
    enable_tee: bool,
    enable_zkml: bool,
    enable_cicd: bool,
    network: String,
}

async fn gather_project_config(args: &InitArgs, config: &Config) -> anyhow::Result<ProjectConfig> {
    // Project name
    let name = if let Some(n) = &args.name {
        n.clone()
    } else {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Project name")
            .default("aethelred-project".to_string())
            .validate_with(|input: &String| {
                if input
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                {
                    Ok(())
                } else {
                    Err("Name must be alphanumeric with dashes or underscores")
                }
            })
            .interact_text()?
    };

    // Industry template
    let templates = vec![
        IndustryTemplate::Finance,
        IndustryTemplate::Healthcare,
        IndustryTemplate::GreenEnergy,
        IndustryTemplate::General,
        IndustryTemplate::Minimal,
    ];

    let template_names: Vec<String> = templates
        .iter()
        .map(|t| format!("{} - {}", t.display_name(), t.description()))
        .collect();

    let template_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select industry template")
        .items(&template_names)
        .default(0)
        .interact()?;

    let template = templates[template_selection];

    // Programming language
    let languages = vec![
        ("Python", "python", "PyTorch, NumPy, @sovereign decorator"),
        ("TypeScript", "typescript", "Node.js, Zero-Knowledge Forms"),
        ("Rust", "rust", "Native performance, compile-time safety"),
        ("Go", "go", "Concurrent processing, microservices"),
    ];

    let language_names: Vec<String> = languages
        .iter()
        .map(|(name, _, desc)| format!("{} - {}", name, desc))
        .collect();

    let lang_selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select programming language")
        .items(&language_names)
        .default(0)
        .interact()?;

    let language = languages[lang_selection].1.to_string();

    // Directory
    let directory = args.dir.clone().unwrap_or_else(|| PathBuf::from(&name));

    // TEE configuration
    let enable_tee = if template.requires_tee() {
        println!(
            "  {} TEE is required for {} template",
            "ℹ️".cyan(),
            template.display_name()
        );
        true
    } else {
        Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Enable TEE (Trusted Execution Environment)?")
            .default(true)
            .interact()?
    };

    // zkML configuration
    let enable_zkml = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable zkML (Zero-Knowledge Machine Learning)?")
        .default(false)
        .interact()?;

    // CI/CD configuration
    let enable_cicd = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Include CI/CD templates (GitHub Actions)?")
        .default(true)
        .interact()?;

    Ok(ProjectConfig {
        name,
        template,
        language,
        directory,
        enable_tee,
        enable_zkml,
        enable_cicd,
        network: config.network.clone(),
    })
}

fn parse_template(template_str: &str) -> IndustryTemplate {
    match template_str.to_lowercase().as_str() {
        "finance" | "banking" | "financial" => IndustryTemplate::Finance,
        "healthcare" | "health" | "medical" => IndustryTemplate::Healthcare,
        "green" | "green-energy" | "esg" | "sustainability" => IndustryTemplate::GreenEnergy,
        "minimal" | "min" | "quick" => IndustryTemplate::Minimal,
        _ => IndustryTemplate::General,
    }
}

// ============================================================================
// Project Creation
// ============================================================================

async fn create_project(config: &ProjectConfig) -> anyhow::Result<()> {
    println!();
    println!("{}", "Creating project...".bold());
    println!();

    let mp = MultiProgress::new();
    let style = ProgressStyle::default_bar()
        .template("{spinner:.green} {prefix:30} [{bar:30.cyan/blue}] {msg}")
        .unwrap()
        .progress_chars("█▓▒░ ");

    let total_steps = 8;

    // Step 1: Create directory structure
    let pb1 = mp.add(ProgressBar::new(100));
    pb1.set_style(style.clone());
    pb1.set_prefix("Creating directories");
    create_directory_structure(&config.directory, config.template, &config.language)?;
    progress_complete(&pb1).await;

    // Step 2: Generate configuration files
    let pb2 = mp.add(ProgressBar::new(100));
    pb2.set_style(style.clone());
    pb2.set_prefix("Generating configs");
    create_config_files(config)?;
    progress_complete(&pb2).await;

    // Step 3: Create source files
    let pb3 = mp.add(ProgressBar::new(100));
    pb3.set_style(style.clone());
    pb3.set_prefix("Creating source files");
    create_source_files(config)?;
    progress_complete(&pb3).await;

    // Step 4: Create compliance configuration
    let pb4 = mp.add(ProgressBar::new(100));
    pb4.set_style(style.clone());
    pb4.set_prefix("Setting up compliance");
    create_compliance_config(config)?;
    progress_complete(&pb4).await;

    // Step 5: Create TEE configuration
    if config.enable_tee {
        let pb5 = mp.add(ProgressBar::new(100));
        pb5.set_style(style.clone());
        pb5.set_prefix("Configuring TEE");
        create_tee_config(config)?;
        progress_complete(&pb5).await;
    }

    // Step 6: Create dependency files
    let pb6 = mp.add(ProgressBar::new(100));
    pb6.set_style(style.clone());
    pb6.set_prefix("Setting up dependencies");
    create_dependency_files(&config.directory, &config.language)?;
    progress_complete(&pb6).await;

    // Step 7: Create CI/CD configuration
    if config.enable_cicd {
        let pb7 = mp.add(ProgressBar::new(100));
        pb7.set_style(style.clone());
        pb7.set_prefix("Creating CI/CD configs");
        create_cicd_config(config)?;
        progress_complete(&pb7).await;
    }

    // Step 8: Initialize git
    let pb8 = mp.add(ProgressBar::new(100));
    pb8.set_style(style.clone());
    pb8.set_prefix("Initializing git");
    init_git(&config.directory)?;
    progress_complete(&pb8).await;

    Ok(())
}

async fn progress_complete(pb: &ProgressBar) {
    for _ in 0..100 {
        pb.inc(1);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    pb.finish_with_message("✓");
}

// ============================================================================
// Directory Structure
// ============================================================================

fn create_directory_structure(
    dir: &PathBuf,
    template: IndustryTemplate,
    lang: &str,
) -> anyhow::Result<()> {
    let base_dirs = match template {
        IndustryTemplate::Minimal => vec!["src", "config"],
        IndustryTemplate::General => vec!["src", "config", "models", "tests", "scripts", "data"],
        IndustryTemplate::Finance => vec![
            "src",
            "src/models",
            "src/pipelines",
            "src/compliance",
            "config",
            "models",
            "tests",
            "tests/integration",
            "scripts",
            "data",
            "docs",
            "deploy",
            ".github/workflows",
        ],
        IndustryTemplate::Healthcare => vec![
            "src",
            "src/models",
            "src/pipelines",
            "src/compliance",
            "src/phi",
            "config",
            "models",
            "tests",
            "tests/hipaa",
            "scripts",
            "data",
            "docs",
            "deploy",
            ".github/workflows",
        ],
        IndustryTemplate::GreenEnergy => vec![
            "src",
            "src/models",
            "src/metrics",
            "src/reporting",
            "config",
            "models",
            "tests",
            "scripts",
            "data",
            "docs",
            "deploy",
            ".github/workflows",
        ],
    };

    fs::create_dir_all(dir)?;
    for d in base_dirs {
        fs::create_dir_all(dir.join(d))?;
    }

    Ok(())
}

// ============================================================================
// Configuration Files
// ============================================================================

fn create_config_files(config: &ProjectConfig) -> anyhow::Result<()> {
    let dir = &config.directory;

    // Main aethelred.toml
    let regulations = config.template.default_regulations();
    let jurisdictions = config.template.default_jurisdictions();

    let config_content = format!(
        r#"# Aethelred Project Configuration
# Generated by aethel init - {template}

[project]
name = "{name}"
version = "0.1.0"
template = "{template_str}"

[network]
default = "{network}"

[network.mainnet]
rpc = "https://rpc.aethelred.io"
chain_id = "aethelred-mainnet-1"

[network.testnet]
rpc = "https://testnet-rpc.aethelred.io"
chain_id = "aethelred-testnet-1"

[network.local]
rpc = "http://localhost:26657"
chain_id = "aethelred-local-1"

[security]
require_tee = {require_tee}
enable_zkml = {enable_zkml}
min_attestation_level = "hardware"

[compliance]
enabled = true
regulations = {regulations:?}
jurisdictions = {jurisdictions:?}
strict_mode = true
auto_audit = true

[model]
default_precision = "fp16"
quantization = "int8"
max_batch_size = 32
require_signature = true

[telemetry]
enabled = true
metrics_endpoint = "https://metrics.aethelred.io"
trace_sampling = 0.1
"#,
        name = config.name,
        template = config.template.display_name(),
        template_str = format!("{:?}", config.template).to_lowercase(),
        network = config.network,
        require_tee = config.enable_tee,
        enable_zkml = config.enable_zkml,
        regulations = regulations,
        jurisdictions = jurisdictions,
    );

    fs::write(dir.join("aethelred.toml"), config_content)?;

    // .env.example
    let env_content = format!(
        r#"# Aethelred Environment Variables
# Copy this file to .env and fill in your values

# Network Configuration
AETHELRED_NETWORK={network}
AETHELRED_RPC_URL=https://testnet-rpc.aethelred.io

# Authentication (NEVER commit real keys!)
AETHELRED_PRIVATE_KEY=
AETHELRED_API_KEY=

# TEE Configuration
AETHELRED_TEE_ENABLED={tee}
AETHELRED_ATTESTATION_MODE=dcap

# Model Configuration
AETHELRED_MODEL_REGISTRY=https://registry.aethelred.io
AETHELRED_MODEL_CACHE_DIR=./.aethelred/models

# Compliance
AETHELRED_COMPLIANCE_STRICT=true
AETHELRED_AUDIT_LOG=./.aethelred/audit.log
"#,
        network = config.network,
        tee = config.enable_tee,
    );

    fs::write(dir.join(".env.example"), env_content)?;

    // .gitignore
    let gitignore = create_gitignore(&config.language);
    fs::write(dir.join(".gitignore"), gitignore)?;

    Ok(())
}

fn create_gitignore(lang: &str) -> String {
    let base = r#"# Aethelred
.aethelred/
*.seal
*.checkpoint
*.attestation
.env

# Secrets (NEVER commit these!)
*.key
*.pem
*.p12
credentials.*
secrets.*

# Data
data/raw/
data/processed/
*.csv
*.parquet
!data/.gitkeep

# Models
models/*.onnx
models/*.pt
models/*.safetensors
!models/.gitkeep

# IDE
.vscode/
.idea/
*.swp
*.swo
.DS_Store
"#;

    let lang_specific = match lang {
        "python" => {
            r#"
# Python
__pycache__/
*.py[cod]
*$py.class
.venv/
venv/
env/
*.egg-info/
dist/
build/
.pytest_cache/
.mypy_cache/
.ruff_cache/
htmlcov/
.coverage
"#
        }
        "typescript" => {
            r#"
# Node/TypeScript
node_modules/
dist/
build/
.next/
coverage/
*.tsbuildinfo
.npm/
"#
        }
        "rust" => {
            r#"
# Rust
target/
Cargo.lock
"#
        }
        "go" => {
            r#"
# Go
vendor/
*.exe
*.test
*.out
"#
        }
        _ => "",
    };

    format!("{}{}", base, lang_specific)
}

// ============================================================================
// Source Files
// ============================================================================

fn create_source_files(config: &ProjectConfig) -> anyhow::Result<()> {
    match config.language.as_str() {
        "python" => create_python_source_files(config),
        "typescript" => create_typescript_source_files(config),
        "rust" => create_rust_source_files(config),
        "go" => create_go_source_files(config),
        _ => Ok(()),
    }
}

fn create_python_source_files(config: &ProjectConfig) -> anyhow::Result<()> {
    let dir = &config.directory;

    // Main file based on template
    let main_content = match config.template {
        IndustryTemplate::Finance => create_finance_python_main(),
        IndustryTemplate::Healthcare => create_healthcare_python_main(),
        IndustryTemplate::GreenEnergy => create_green_energy_python_main(),
        _ => create_general_python_main(),
    };

    fs::write(dir.join("main.py"), main_content)?;
    fs::write(dir.join("src/__init__.py"), "# Aethelred Project\n")?;

    Ok(())
}

fn create_finance_python_main() -> String {
    r#"#!/usr/bin/env python3
"""
Aethelred Finance Project - Credit Scoring & Fraud Detection

This template demonstrates verifiable AI for financial services with:
- Credit scoring with Digital Seals
- Fraud detection with TEE execution
- UAE/GDPR compliance integration
"""

import asyncio
from typing import Optional, Dict, Any

from aethelred import (
    AethelredClient,
    Network,
    Tensor,
    Hardware,
    Compliance,
)
from aethelred.sovereign import sovereign, SovereignData
from aethelred.nn import Module, Linear, Sequential, ReLU, Dropout
from aethelred.compliance import ComplianceEngine, Jurisdiction


class CreditScoringModel(Module):
    """
    Credit scoring model with verifiable inference.

    This model runs inside a TEE and generates Digital Seals
    for each credit decision, providing regulatory proof.
    """

    def __init__(
        self,
        input_features: int = 128,
        hidden_dim: int = 256,
        output_dim: int = 1,
    ):
        super().__init__()
        self.network = Sequential([
            Linear(input_features, hidden_dim),
            ReLU(),
            Dropout(0.2),
            Linear(hidden_dim, hidden_dim // 2),
            ReLU(),
            Dropout(0.2),
            Linear(hidden_dim // 2, output_dim),
        ])

    def forward(self, x: Tensor) -> Tensor:
        """Forward pass returns credit score probability."""
        return self.network(x).sigmoid()


@sovereign(
    hardware=Hardware.TEE_REQUIRED,
    compliance=Compliance.UAE_DATA_RESIDENCY | Compliance.GDPR,
    jurisdiction=Jurisdiction.UAE,
)
async def run_credit_scoring(
    client: AethelredClient,
    model: CreditScoringModel,
    applicant_data: SovereignData,
) -> Dict[str, Any]:
    """
    Execute credit scoring with full compliance and attestation.

    This function:
    1. Validates data residency requirements
    2. Executes inference inside TEE
    3. Generates Digital Seal for audit
    4. Returns verifiable credit decision
    """
    # Validate compliance before processing
    compliance = ComplianceEngine()
    compliance.validate(applicant_data, Jurisdiction.UAE)

    # Execute model inference
    features = applicant_data.to_tensor()
    score = model(features)

    # Create verifiable Digital Seal
    seal = await client.create_seal(
        model_output=score,
        input_hash=applicant_data.hash(),
        purpose="credit_scoring",
        include_attestation=True,
    )

    return {
        "credit_score": float(score.item()),
        "seal_id": seal.id,
        "attestation": seal.attestation,
        "compliant": True,
        "jurisdictions": ["UAE", "EU"],
    }


async def main():
    print("🏦 Aethelred Finance Project - Credit Scoring")
    print("=" * 50)

    # Initialize client
    client = await AethelredClient.create(
        network=Network.TESTNET,
        require_tee=True,
    )
    print(f"✓ Connected to {client.network}")
    print(f"✓ TEE Available: {client.has_tee}")

    # Initialize model
    model = CreditScoringModel()
    print(f"✓ Model loaded: {model.num_parameters():,} parameters")

    # Example inference with sovereign data
    applicant = SovereignData.from_dict({
        "income": 75000,
        "debt_ratio": 0.35,
        "credit_history_months": 84,
        "employment_years": 5,
    }, jurisdiction=Jurisdiction.UAE)

    result = await run_credit_scoring(client, model, applicant)

    print()
    print("📊 Credit Scoring Result:")
    print(f"   Score: {result['credit_score']:.2%}")
    print(f"   Seal ID: {result['seal_id']}")
    print(f"   Compliant: {result['compliant']}")
    print(f"   Jurisdictions: {', '.join(result['jurisdictions'])}")


if __name__ == "__main__":
    asyncio.run(main())
"#
    .to_string()
}

fn create_healthcare_python_main() -> String {
    r#"#!/usr/bin/env python3
"""
Aethelred Healthcare Project - Medical AI with HIPAA Compliance

This template demonstrates verifiable AI for healthcare with:
- PHI (Protected Health Information) protection
- HIPAA-compliant data processing
- Medical imaging analysis with attestation
"""

import asyncio
from typing import Optional, Dict, Any, List

from aethelred import (
    AethelredClient,
    Network,
    Tensor,
    Hardware,
    Compliance,
)
from aethelred.sovereign import sovereign, SovereignData, PHIData
from aethelred.nn import Module, Conv2d, Linear, Sequential, ReLU
from aethelred.compliance import ComplianceEngine, Jurisdiction, HIPAA


class MedicalImagingModel(Module):
    """
    Medical imaging classification model with PHI protection.

    All inference runs inside TEE with automatic de-identification
    of any logged data to maintain HIPAA compliance.
    """

    def __init__(self, num_classes: int = 5):
        super().__init__()
        self.features = Sequential([
            Conv2d(1, 32, kernel_size=3, padding=1),
            ReLU(),
            Conv2d(32, 64, kernel_size=3, padding=1),
            ReLU(),
        ])
        self.classifier = Sequential([
            Linear(64 * 56 * 56, 256),
            ReLU(),
            Linear(256, num_classes),
        ])

    def forward(self, x: Tensor) -> Tensor:
        features = self.features(x)
        features = features.flatten(start_dim=1)
        return self.classifier(features)


@sovereign(
    hardware=Hardware.TEE_REQUIRED,
    compliance=Compliance.HIPAA | Compliance.HITECH,
    phi_protection=True,
    audit_required=True,
)
async def analyze_medical_image(
    client: AethelredClient,
    model: MedicalImagingModel,
    patient_scan: PHIData,
) -> Dict[str, Any]:
    """
    Analyze medical image with full HIPAA compliance.

    This function:
    1. Validates HIPAA authorization
    2. De-identifies logging automatically
    3. Executes inference in TEE
    4. Generates audit trail with Digital Seal
    """
    # HIPAA authorization check
    hipaa = HIPAA()
    hipaa.validate_authorization(patient_scan)

    # Execute analysis
    image_tensor = patient_scan.to_tensor()
    predictions = model(image_tensor)

    # Create verifiable seal (PHI automatically excluded)
    seal = await client.create_seal(
        model_output=predictions,
        input_hash=patient_scan.de_identified_hash(),
        purpose="medical_diagnosis",
        include_attestation=True,
        audit_level="full",
    )

    return {
        "predictions": predictions.softmax(dim=-1).tolist(),
        "seal_id": seal.id,
        "hipaa_compliant": True,
        "phi_protected": True,
    }


async def main():
    print("🏥 Aethelred Healthcare Project - Medical AI")
    print("=" * 50)

    # Initialize client with HIPAA mode
    client = await AethelredClient.create(
        network=Network.TESTNET,
        require_tee=True,
        hipaa_mode=True,
    )
    print(f"✓ Connected to {client.network}")
    print(f"✓ HIPAA Mode: Enabled")
    print(f"✓ PHI Protection: Active")

    # Initialize model
    model = MedicalImagingModel(num_classes=5)
    print(f"✓ Model loaded: {model.num_parameters():,} parameters")

    # Example inference (using synthetic data)
    patient_scan = PHIData.synthetic(
        shape=[1, 1, 224, 224],
        patient_id="DEIDENTIFIED",
    )

    result = await analyze_medical_image(client, model, patient_scan)

    print()
    print("📊 Analysis Result:")
    print(f"   Seal ID: {result['seal_id']}")
    print(f"   HIPAA Compliant: {result['hipaa_compliant']}")
    print(f"   PHI Protected: {result['phi_protected']}")


if __name__ == "__main__":
    asyncio.run(main())
"#
    .to_string()
}

fn create_green_energy_python_main() -> String {
    r#"#!/usr/bin/env python3
"""
Aethelred Green Energy Project - ESG & Carbon Tracking

This template demonstrates verifiable AI for sustainability with:
- Carbon footprint tracking and verification
- ESG metrics calculation with attestation
- Regulatory compliance (EU CSRD, SEC ESG)
"""

import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime

from aethelred import (
    AethelredClient,
    Network,
    Tensor,
    Hardware,
    Compliance,
)
from aethelred.sovereign import sovereign, SovereignData
from aethelred.nn import Module, Linear, LSTM, Sequential, ReLU
from aethelred.compliance import ComplianceEngine, Jurisdiction


class CarbonFootprintModel(Module):
    """
    Carbon footprint prediction model with verifiable outputs.

    Generates attested carbon metrics that can be used
    for regulatory reporting and carbon credit verification.
    """

    def __init__(self, input_features: int = 64, hidden_dim: int = 128):
        super().__init__()
        self.encoder = LSTM(input_features, hidden_dim, num_layers=2)
        self.predictor = Sequential([
            Linear(hidden_dim, 64),
            ReLU(),
            Linear(64, 3),  # CO2, CH4, N2O emissions
        ])

    def forward(self, x: Tensor) -> Tensor:
        _, (hidden, _) = self.encoder(x)
        return self.predictor(hidden[-1])


@sovereign(
    hardware=Hardware.TEE_PREFERRED,
    compliance=Compliance.EU_CSRD | Compliance.SEC_ESG,
    audit_required=True,
)
async def calculate_carbon_footprint(
    client: AethelredClient,
    model: CarbonFootprintModel,
    energy_data: SovereignData,
    reporting_period: str,
) -> Dict[str, Any]:
    """
    Calculate verifiable carbon footprint with regulatory attestation.

    This function:
    1. Processes energy consumption data
    2. Calculates emissions using verified model
    3. Generates Digital Seal for regulatory proof
    4. Produces audit-ready documentation
    """
    # Process energy data
    features = energy_data.to_tensor()
    emissions = model(features)

    # Convert to CO2 equivalent
    co2e = emissions[0] + (emissions[1] * 25) + (emissions[2] * 298)

    # Create verifiable seal
    seal = await client.create_seal(
        model_output=emissions,
        input_hash=energy_data.hash(),
        purpose="carbon_footprint_calculation",
        include_attestation=True,
        metadata={
            "reporting_period": reporting_period,
            "standard": "GHG Protocol",
        },
    )

    return {
        "co2_tonnes": float(emissions[0]),
        "ch4_tonnes": float(emissions[1]),
        "n2o_tonnes": float(emissions[2]),
        "co2e_tonnes": float(co2e),
        "seal_id": seal.id,
        "reporting_period": reporting_period,
        "verification_status": "attested",
    }


async def main():
    print("🌱 Aethelred Green Energy Project - Carbon Tracking")
    print("=" * 50)

    # Initialize client
    client = await AethelredClient.create(
        network=Network.TESTNET,
        require_tee=False,  # TEE preferred but not required
    )
    print(f"✓ Connected to {client.network}")

    # Initialize model
    model = CarbonFootprintModel()
    print(f"✓ Model loaded: {model.num_parameters():,} parameters")

    # Example calculation
    energy_data = SovereignData.from_dict({
        "electricity_kwh": 1_500_000,
        "natural_gas_mj": 250_000,
        "fuel_liters": 15_000,
    })

    result = await calculate_carbon_footprint(
        client,
        model,
        energy_data,
        reporting_period="2024-Q1",
    )

    print()
    print("📊 Carbon Footprint Report:")
    print(f"   CO2: {result['co2_tonnes']:,.1f} tonnes")
    print(f"   CH4: {result['ch4_tonnes']:,.1f} tonnes")
    print(f"   N2O: {result['n2o_tonnes']:,.1f} tonnes")
    print(f"   CO2e: {result['co2e_tonnes']:,.1f} tonnes")
    print(f"   Seal ID: {result['seal_id']}")
    print(f"   Verification: {result['verification_status']}")


if __name__ == "__main__":
    asyncio.run(main())
"#
    .to_string()
}

fn create_general_python_main() -> String {
    r#"#!/usr/bin/env python3
"""
Aethelred AI Project

A general-purpose template for building verifiable AI applications
on the Aethelred blockchain.
"""

import asyncio
from typing import Dict, Any

from aethelred import AethelredClient, Network, Tensor
from aethelred.nn import Module, Linear, Sequential, ReLU


class SimpleModel(Module):
    """Simple neural network with verifiable inference."""

    def __init__(self, input_dim: int, hidden_dim: int, output_dim: int):
        super().__init__()
        self.layers = Sequential([
            Linear(input_dim, hidden_dim),
            ReLU(),
            Linear(hidden_dim, output_dim),
        ])

    def forward(self, x: Tensor) -> Tensor:
        return self.layers(x)


async def main():
    print("🚀 Aethelred AI Project")
    print("=" * 40)

    # Initialize client
    client = await AethelredClient.create(Network.TESTNET)
    print(f"✓ Connected to {client.network}")

    # Create model
    model = SimpleModel(784, 256, 10)
    print(f"✓ Model created: {model.num_parameters():,} parameters")

    # Example inference
    x = Tensor.randn([1, 784])
    output = model(x)
    print(f"✓ Inference output shape: {output.shape}")

    # Create Digital Seal
    seal = await client.create_seal(output)
    print(f"✓ Digital Seal created: {seal.id}")


if __name__ == "__main__":
    asyncio.run(main())
"#
    .to_string()
}

fn create_typescript_source_files(config: &ProjectConfig) -> anyhow::Result<()> {
    let dir = &config.directory;

    let main_content = r#"/**
 * Aethelred AI Project
 */

import { AethelredClient, Network, Tensor } from '@aethelred/sdk';
import { Module, Linear, Sequential } from '@aethelred/sdk/nn';

class SimpleModel extends Module {
  private layers: Sequential;

  constructor(inputDim: number, hiddenDim: number, outputDim: number) {
    super('SimpleModel');
    this.layers = new Sequential([
      new Linear(inputDim, hiddenDim),
      new Linear(hiddenDim, outputDim),
    ]);
  }

  forward(x: Tensor): Tensor {
    return this.layers.forward(x);
  }
}

async function main() {
  console.log('🚀 Aethelred AI Project');
  console.log('='.repeat(40));

  // Initialize client
  const client = await AethelredClient.create(Network.Testnet);
  console.log(`✓ Connected to ${client.network}`);

  // Create model
  const model = new SimpleModel(784, 256, 10);
  console.log(`✓ Model created: ${model.numParameters().toLocaleString()} parameters`);

  // Example inference
  const x = Tensor.randn([1, 784]);
  const output = model.forward(x);
  console.log(`✓ Inference output shape: [${output.shape.join(', ')}]`);

  // Create Digital Seal
  const seal = await client.createSeal(output);
  console.log(`✓ Digital Seal created: ${seal.id}`);
}

main().catch(console.error);
"#;

    fs::write(dir.join("src/index.ts"), main_content)?;

    // tsconfig.json
    let tsconfig = r#"{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "lib": ["ES2022"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist"]
}
"#;
    fs::write(dir.join("tsconfig.json"), tsconfig)?;

    Ok(())
}

fn create_rust_source_files(config: &ProjectConfig) -> anyhow::Result<()> {
    let dir = &config.directory;

    let main_content = r#"//! Aethelred AI Project

use aethelred_sdk::{
    AethelredClient, ClientConfig, Network,
    zktensor::ZkTensor,
    sovereign::{Sovereign, Jurisdiction},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("🚀 Aethelred AI Project");
    println!("{}", "=".repeat(40));

    // Initialize client
    let config = ClientConfig {
        rpc_url: "https://testnet-rpc.aethelred.io".into(),
        chain_id: "aethelred-testnet-1".into(),
        ..Default::default()
    };

    let mut client = AethelredClient::new(config);
    client.connect().await?;
    println!("✓ Connected to testnet");

    // Create ZK tensor
    let tensor = ZkTensor::from_vec(vec![1.0, 2.0, 3.0, 4.0]);
    println!("✓ ZkTensor created: {:?}", tensor.shape());

    // Example computation with proof
    let result = tensor.sum();
    println!("✓ Sum: {:?}", result.value());

    // Verify the proof
    assert!(result.verify().is_ok());
    println!("✓ Proof verified");

    Ok(())
}
"#;

    fs::write(dir.join("src/main.rs"), main_content)?;

    Ok(())
}

fn create_go_source_files(config: &ProjectConfig) -> anyhow::Result<()> {
    let dir = &config.directory;

    let main_content = r#"// Aethelred AI Project
package main

import (
	"fmt"
	"log"

	aethelred "github.com/aethelred/sdk"
)

func main() {
	fmt.Println("🚀 Aethelred AI Project")
	fmt.Println("========================================")

	// Initialize client
	client, err := aethelred.NewClient(aethelred.Testnet)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	fmt.Printf("✓ Connected to %s\n", client.Network)

	// Get chain info
	info, err := client.ChainInfo()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("✓ Block height: %d\n", info.BlockHeight)
}
"#;

    fs::write(dir.join("main.go"), main_content)?;

    Ok(())
}

// ============================================================================
// Compliance Configuration
// ============================================================================

fn create_compliance_config(config: &ProjectConfig) -> anyhow::Result<()> {
    let dir = &config.directory;

    let compliance_content = format!(
        r#"# Compliance Configuration
# Generated for {template} template

[compliance]
version = "2.0"
enabled = true
strict_mode = true

[compliance.regulations]
enabled = {regulations:?}
auto_detect = true

[compliance.jurisdictions]
primary = {jurisdictions:?}
secondary = []

[compliance.data_classification]
default = "confidential"
require_explicit = true

[compliance.audit]
enabled = true
retention_days = 2555
sign_with_attestation = true
export_format = "json"

[compliance.alerts]
enabled = true
channels = ["log"]
severity_threshold = "warning"
"#,
        template = config.template.display_name(),
        regulations = config.template.default_regulations(),
        jurisdictions = config.template.default_jurisdictions(),
    );

    fs::write(dir.join("config/compliance.toml"), compliance_content)?;

    Ok(())
}

// ============================================================================
// TEE Configuration
// ============================================================================

fn create_tee_config(config: &ProjectConfig) -> anyhow::Result<()> {
    let dir = &config.directory;

    let tee_content = r#"# TEE (Trusted Execution Environment) Configuration

[tee]
enabled = true
platform = "auto"  # auto, intel_sgx, amd_sev, aws_nitro

[tee.attestation]
mode = "dcap"  # dcap, epid, azure, gcp
verify_remote = true
cache_reports = true

[tee.enclave]
max_size_mb = 128
heap_size_mb = 64
stack_size_kb = 256
threads = 4

[tee.security]
debug_mode = false
seal_data = true
mitigation_level = "hardware"
"#;

    fs::write(dir.join("config/tee.toml"), tee_content)?;

    Ok(())
}

// ============================================================================
// CI/CD Configuration
// ============================================================================

fn create_cicd_config(config: &ProjectConfig) -> anyhow::Result<()> {
    let dir = &config.directory;

    let workflow = r#"name: Aethelred CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Compliance Check
        run: aethelred compliance check --strict

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Tests
        run: aethelred dev test

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Security Scan
        run: aethelred compliance analyze --depth deep
"#;

    fs::write(dir.join(".github/workflows/ci.yml"), workflow)?;

    Ok(())
}

// ============================================================================
// Dependency Files
// ============================================================================

fn create_dependency_files(dir: &PathBuf, lang: &str) -> anyhow::Result<()> {
    match lang {
        "python" => {
            let pyproject = r#"[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "aethelred-project"
version = "0.1.0"
description = "Aethelred AI Project"
requires-python = ">=3.10"
dependencies = [
    "aethelred-sdk>=2.0.0",
    "numpy>=1.24.0",
    "torch>=2.0.0",
    "pydantic>=2.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-asyncio>=0.21.0",
    "black>=23.0.0",
    "ruff>=0.1.0",
    "mypy>=1.0.0",
]
"#;
            fs::write(dir.join("pyproject.toml"), pyproject)?;
        }
        "typescript" => {
            let package = r#"{
  "name": "aethelred-project",
  "version": "0.1.0",
  "description": "Aethelred AI Project",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "build": "tsc",
    "dev": "ts-node src/index.ts",
    "test": "jest",
    "lint": "eslint src/",
    "format": "prettier --write src/"
  },
  "dependencies": {
    "@aethelred/sdk": "^2.0.0"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "typescript": "^5.0.0",
    "ts-node": "^10.9.0",
    "jest": "^29.0.0",
    "@types/jest": "^29.0.0",
    "ts-jest": "^29.0.0",
    "eslint": "^8.0.0",
    "prettier": "^3.0.0"
  }
}
"#;
            fs::write(dir.join("package.json"), package)?;
        }
        "rust" => {
            let cargo = r#"[package]
name = "aethelred-project"
version = "0.1.0"
edition = "2021"

[dependencies]
aethelred-sdk = "2.0"
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[dev-dependencies]
criterion = "0.5"
"#;
            fs::write(dir.join("Cargo.toml"), cargo)?;
        }
        "go" => {
            let gomod = r#"module aethelred-project

go 1.21

require github.com/aethelred/sdk v2.0.0
"#;
            fs::write(dir.join("go.mod"), gomod)?;
        }
        _ => {}
    }

    Ok(())
}

// ============================================================================
// Git Initialization
// ============================================================================

fn init_git(dir: &PathBuf) -> anyhow::Result<()> {
    let git_dir = dir.join(".git");
    if !git_dir.exists() {
        std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(dir)
            .output()
            .ok();
    }
    Ok(())
}

// ============================================================================
// Success Message
// ============================================================================

fn display_success(config: &ProjectConfig) {
    println!();
    println!(
        "{}",
        "╔════════════════════════════════════════════════════════════════════╗".green()
    );
    println!(
        "{}",
        "║                    ✅ PROJECT CREATED SUCCESSFULLY                 ║".green()
    );
    println!(
        "{}",
        "╚════════════════════════════════════════════════════════════════════╝".green()
    );
    println!();

    println!(
        "  {} {}",
        "📁 Location:".bold(),
        config.directory.display().to_string().cyan()
    );
    println!(
        "  {} {}",
        "📋 Template:".bold(),
        config.template.display_name().cyan()
    );
    println!();

    println!("{}", "Next steps:".bold().underline());
    println!();
    println!("  1. cd {}", config.name.cyan());

    match config.language.as_str() {
        "python" => {
            println!("  2. python -m venv .venv");
            println!("  3. source .venv/bin/activate");
            println!("  4. pip install -e .");
            println!("  5. python main.py");
        }
        "typescript" => {
            println!("  2. npm install");
            println!("  3. npm run dev");
        }
        "rust" => {
            println!("  2. cargo build");
            println!("  3. cargo run");
        }
        "go" => {
            println!("  2. go mod tidy");
            println!("  3. go run main.go");
        }
        _ => {}
    }

    println!();
    println!("{}", "Useful commands:".bold().underline());
    println!();
    println!(
        "  {} - Check compliance",
        "aethelred compliance check".green()
    );
    println!(
        "  {} - Detect hardware",
        "aethelred hardware detect".green()
    );
    println!(
        "  {} - Run development server",
        "aethelred dev serve".green()
    );
    println!();
    println!(
        "  📚 Documentation: {}",
        "https://docs.aethelred.io".cyan().underline()
    );
    println!();
}
