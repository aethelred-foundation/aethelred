//! # AI Gas Profiler
//!
//! **"The CFO in the Code"**
//!
//! This module provides real-time cost estimation for AI computations.
//! Before executing, users see:
//!
//! - AETHEL token cost
//! - Carbon footprint (kg CO2)
//! - Energy consumption (Wh)
//! - Comparison to cloud alternatives
//!
//! Cloud pricing defaults are built in, but can be overridden at runtime via:
//! - `AIGasProfiler::set_cloud_pricing(...)`
//! - `AIGasProfiler::update_cloud_pricing_from_json(...)`
//! - `AIGasProfiler::try_new_from_env()` with:
//!   - `AETHELRED_SANDBOX_CLOUD_PRICING_FILE`
//!   - `AETHELRED_SANDBOX_CLOUD_PRICING_JSON`
//!
//! ## The Cost Dashboard
//!
//! ```text
//! ╔═══════════════════════════════════════════════════════════════════════════════╗
//! ║                        💰 AI GAS PROFILER                                     ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║                                                                               ║
//! ║  MODEL: Credit Scoring v2 (XGBoost → ONNX)                                   ║
//! ║  INPUT: 1,000 loan applications                                              ║
//! ║                                                                               ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║  COST BREAKDOWN                                                               ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║                                                                               ║
//! ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
//! ║  │                                                                         │ ║
//! ║  │   COMPUTE         ████████████████░░░░░░░░░░░░░░░░░░  3.2 AETHEL       │ ║
//! ║  │   TEE OVERHEAD    ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░  1.1 AETHEL       │ ║
//! ║  │   PROOF GEN       ████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.7 AETHEL       │ ║
//! ║  │   STORAGE         ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0.2 AETHEL       │ ║
//! ║  │   ─────────────────────────────────────────────────────────────────    │ ║
//! ║  │   TOTAL                                               5.2 AETHEL       │ ║
//! ║  │                                                                         │ ║
//! ║  └─────────────────────────────────────────────────────────────────────────┘ ║
//! ║                                                                               ║
//! ║  ENVIRONMENTAL IMPACT                                                         ║
//! ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
//! ║  │   ⚡ Energy:        420 Wh                                               │ ║
//! ║  │   🌍 Carbon:        0.18 kg CO2                                          │ ║
//! ║  │   🌳 Trees needed:  0.008 trees/year to offset                           │ ║
//! ║  └─────────────────────────────────────────────────────────────────────────┘ ║
//! ║                                                                               ║
//! ║  CLOUD COMPARISON                                                             ║
//! ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
//! ║  │   AWS SageMaker:   $12.50 (2.4x more expensive)                         │ ║
//! ║  │   Azure ML:        $14.20 (2.7x more expensive)                         │ ║
//! ║  │   GCP Vertex:      $11.80 (2.3x more expensive)                         │ ║
//! ║  │   Aethelred:       5.2 AETHEL ≈ $5.20 ✅ BEST VALUE                     │ ║
//! ║  └─────────────────────────────────────────────────────────────────────────┘ ║
//! ║                                                                               ║
//! ╚═══════════════════════════════════════════════════════════════════════════════╝
//! ```

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs};

use crate::core::HardwareTarget;

// ============================================================================
// Cost Components
// ============================================================================

/// Gas cost breakdown for an AI computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasCostBreakdown {
    /// Compute cost (GPU/CPU cycles)
    pub compute: CostComponent,
    /// TEE overhead cost
    pub tee_overhead: CostComponent,
    /// Proof generation cost (zkML)
    pub proof_generation: CostComponent,
    /// Storage cost (for results, logs)
    pub storage: CostComponent,
    /// Network cost (data transfer)
    pub network: CostComponent,
    /// Total in AETHEL tokens
    pub total_aethel: f64,
    /// Total in USD (at current rate)
    pub total_usd: f64,
}

impl GasCostBreakdown {
    pub fn total(&self) -> f64 {
        self.compute.aethel
            + self.tee_overhead.aethel
            + self.proof_generation.aethel
            + self.storage.aethel
            + self.network.aethel
    }
}

/// Individual cost component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostComponent {
    /// Cost in AETHEL
    pub aethel: f64,
    /// Percentage of total
    pub percentage: f64,
    /// Description
    pub description: String,
}

// ============================================================================
// Model Specification
// ============================================================================

/// Specification of an AI model for cost estimation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSpec {
    /// Model name
    pub name: String,
    /// Model type
    pub model_type: ModelType,
    /// Number of parameters
    pub parameters: u64,
    /// Input dimensions
    pub input_dims: Vec<u32>,
    /// Output dimensions
    pub output_dims: Vec<u32>,
    /// Estimated FLOPs per inference
    pub flops_per_inference: u64,
    /// Model size in bytes
    pub size_bytes: u64,
    /// Requires TEE
    pub requires_tee: bool,
    /// Requires zkML proof
    pub requires_zkml: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelType {
    /// Tree-based (XGBoost, LightGBM)
    TreeBased,
    /// Neural Network
    NeuralNetwork,
    /// Transformer
    Transformer,
    /// CNN
    Convolutional,
    /// RNN/LSTM
    Recurrent,
    /// Linear/Logistic
    Linear,
    /// Custom
    Custom,
}

impl ModelSpec {
    /// Create a credit scoring model spec
    pub fn credit_scoring() -> Self {
        ModelSpec {
            name: "Credit Scoring v2 (XGBoost → ONNX)".to_string(),
            model_type: ModelType::TreeBased,
            parameters: 50_000,
            input_dims: vec![100], // 100 features
            output_dims: vec![1],  // Single score
            flops_per_inference: 500_000,
            size_bytes: 2_000_000, // 2MB
            requires_tee: true,
            requires_zkml: true,
        }
    }

    /// Create a fraud detection model spec
    pub fn fraud_detection() -> Self {
        ModelSpec {
            name: "Fraud Detection Neural Net".to_string(),
            model_type: ModelType::NeuralNetwork,
            parameters: 500_000,
            input_dims: vec![256],
            output_dims: vec![2], // Fraud / Not Fraud
            flops_per_inference: 5_000_000,
            size_bytes: 10_000_000, // 10MB
            requires_tee: true,
            requires_zkml: true,
        }
    }

    /// Create a large language model spec
    pub fn llm_inference() -> Self {
        ModelSpec {
            name: "LLM-7B Inference".to_string(),
            model_type: ModelType::Transformer,
            parameters: 7_000_000_000,
            input_dims: vec![2048],
            output_dims: vec![2048],
            flops_per_inference: 14_000_000_000_000, // 14 TFLOPs
            size_bytes: 14_000_000_000,              // 14GB
            requires_tee: true,
            requires_zkml: false, // Too expensive for zkML
        }
    }
}

// ============================================================================
// Environmental Impact
// ============================================================================

/// Environmental impact of computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentalImpact {
    /// Energy consumption in Watt-hours
    pub energy_wh: f64,
    /// Carbon footprint in kg CO2
    pub carbon_kg: f64,
    /// Water usage in liters
    pub water_liters: f64,
    /// Trees needed to offset per year
    pub trees_per_year: f64,
    /// Comparison to household activities
    pub comparison: String,
}

impl EnvironmentalImpact {
    /// Calculate from energy consumption
    pub fn from_energy(energy_wh: f64, location: &str) -> Self {
        // Carbon intensity varies by region (kg CO2 per kWh)
        let carbon_intensity = match location {
            "AE" => 0.42, // UAE (mostly natural gas)
            "SG" => 0.41, // Singapore
            "US" => 0.38, // USA average
            "EU" => 0.23, // EU average
            "NO" => 0.02, // Norway (mostly hydro)
            "FR" => 0.06, // France (mostly nuclear)
            _ => 0.40,    // World average
        };

        let energy_kwh = energy_wh / 1000.0;
        let carbon_kg = energy_kwh * carbon_intensity;

        // 1 tree absorbs ~22 kg CO2 per year
        let trees_per_year = carbon_kg / 22.0;

        // Water usage for data centers (liters per kWh)
        let water_liters = energy_kwh * 1.8;

        let comparison = if energy_wh < 100.0 {
            "Less than boiling a kettle".to_string()
        } else if energy_wh < 500.0 {
            "Similar to running a laptop for 2 hours".to_string()
        } else if energy_wh < 2000.0 {
            "Similar to a load of laundry".to_string()
        } else if energy_wh < 10000.0 {
            "Similar to charging an EV for 30 miles".to_string()
        } else {
            "Similar to a household's daily consumption".to_string()
        };

        EnvironmentalImpact {
            energy_wh,
            carbon_kg,
            water_liters,
            trees_per_year,
            comparison,
        }
    }
}

// ============================================================================
// Cloud Comparison
// ============================================================================

/// Comparison with cloud providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudComparison {
    /// Provider name
    pub provider: String,
    /// Estimated cost in USD
    pub cost_usd: f64,
    /// Cost ratio vs Aethelred
    pub cost_ratio: f64,
    /// Notes
    pub notes: String,
}

/// Cost profile for a cloud provider (priced per 100 inferences).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudProviderPricing {
    /// Base cost for tree-based models per 100 inferences.
    pub tree_based_cost_per_100: f64,
    /// Base cost for neural network models per 100 inferences.
    pub neural_network_cost_per_100: f64,
    /// Base cost for transformer models per 100 inferences.
    pub transformer_cost_per_100: f64,
    /// Default/fallback cost per 100 inferences.
    pub default_cost_per_100: f64,
    /// Extra multiplier applied when TEE is required.
    pub tee_overhead_multiplier: f64,
}

impl CloudProviderPricing {
    fn estimate_cost_usd(&self, model: &ModelSpec, batch_size: u32) -> f64 {
        let base_rate = match model.model_type {
            ModelType::TreeBased => self.tree_based_cost_per_100,
            ModelType::NeuralNetwork => self.neural_network_cost_per_100,
            ModelType::Transformer => self.transformer_cost_per_100,
            _ => self.default_cost_per_100,
        };
        let base_cost = base_rate * batch_size as f64 / 100.0;
        let tee_overhead = if model.requires_tee {
            base_cost * self.tee_overhead_multiplier
        } else {
            0.0
        };
        base_cost + tee_overhead
    }
}

/// Updatable cloud pricing table used by the AI gas profiler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudPricingConfig {
    pub aws_sagemaker: CloudProviderPricing,
    pub azure_ml: CloudProviderPricing,
    pub gcp_vertex: CloudProviderPricing,
}

const CLOUD_PRICING_FILE_ENV: &str = "AETHELRED_SANDBOX_CLOUD_PRICING_FILE";
const CLOUD_PRICING_JSON_ENV: &str = "AETHELRED_SANDBOX_CLOUD_PRICING_JSON";
const DEFAULT_CLOUD_PRICING_JSON: &str = include_str!("../../config/default_cloud_pricing.json");

impl Default for CloudPricingConfig {
    fn default() -> Self {
        Self::from_embedded_defaults().unwrap_or_else(|_| Self::fallback_defaults())
    }
}

impl CloudPricingConfig {
    fn fallback_defaults() -> Self {
        CloudPricingConfig {
            aws_sagemaker: CloudProviderPricing {
                tree_based_cost_per_100: 0.01,
                neural_network_cost_per_100: 0.02,
                transformer_cost_per_100: 0.50,
                default_cost_per_100: 0.01,
                tee_overhead_multiplier: 0.30,
            },
            azure_ml: CloudProviderPricing {
                tree_based_cost_per_100: 0.012,
                neural_network_cost_per_100: 0.022,
                transformer_cost_per_100: 0.55,
                default_cost_per_100: 0.012,
                tee_overhead_multiplier: 0.0,
            },
            gcp_vertex: CloudProviderPricing {
                tree_based_cost_per_100: 0.009,
                neural_network_cost_per_100: 0.018,
                transformer_cost_per_100: 0.45,
                default_cost_per_100: 0.009,
                tee_overhead_multiplier: 0.0,
            },
        }
    }

    fn from_embedded_defaults() -> Result<Self, serde_json::Error> {
        Self::from_json(DEFAULT_CLOUD_PRICING_JSON)
    }

    /// Parse cloud pricing from JSON.
    pub fn from_json(config_json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(config_json)
    }

    /// Parse cloud pricing from a JSON file.
    pub fn from_file(path: &str) -> Result<Self, String> {
        let raw_json = fs::read_to_string(path)
            .map_err(|err| format!("failed to read cloud pricing file: {}", err))?;
        Self::from_json(&raw_json).map_err(|err| format!("invalid cloud pricing JSON: {}", err))
    }

    /// Load cloud pricing from environment variables.
    ///
    /// Priority:
    /// 1) `AETHELRED_SANDBOX_CLOUD_PRICING_FILE` (path to JSON file)
    /// 2) `AETHELRED_SANDBOX_CLOUD_PRICING_JSON` (raw JSON payload)
    pub fn from_env() -> Result<Option<Self>, String> {
        match std::env::var(CLOUD_PRICING_FILE_ENV) {
            Ok(path) => return Self::from_file(path.trim()).map(Some),
            Err(std::env::VarError::NotPresent) => {}
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(format!("{} is not valid UTF-8", CLOUD_PRICING_FILE_ENV));
            }
        }

        match std::env::var(CLOUD_PRICING_JSON_ENV) {
            Ok(raw_json) => Self::from_json(&raw_json)
                .map(Some)
                .map_err(|err| format!("invalid cloud pricing JSON: {}", err)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => {
                Err(format!("{} is not valid UTF-8", CLOUD_PRICING_JSON_ENV))
            }
        }
    }
}

/// Cloud provider pricing estimation helpers.
pub struct CloudPricing;

impl CloudPricing {
    fn estimate(
        provider: &str,
        notes: &str,
        model: &ModelSpec,
        batch_size: u32,
        pricing: &CloudProviderPricing,
    ) -> CloudComparison {
        CloudComparison {
            provider: provider.to_string(),
            cost_usd: pricing.estimate_cost_usd(model, batch_size),
            cost_ratio: 0.0,
            notes: notes.to_string(),
        }
    }

    pub fn estimate_aws_sagemaker(
        model: &ModelSpec,
        batch_size: u32,
        pricing: &CloudProviderPricing,
    ) -> CloudComparison {
        Self::estimate(
            "AWS SageMaker",
            "ml.m5.large with optional Nitro enclave",
            model,
            batch_size,
            pricing,
        )
    }

    pub fn estimate_azure_ml(
        model: &ModelSpec,
        batch_size: u32,
        pricing: &CloudProviderPricing,
    ) -> CloudComparison {
        Self::estimate(
            "Azure ML",
            "Standard D2s v3 with Confidential Computing",
            model,
            batch_size,
            pricing,
        )
    }

    pub fn estimate_gcp_vertex(
        model: &ModelSpec,
        batch_size: u32,
        pricing: &CloudProviderPricing,
    ) -> CloudComparison {
        Self::estimate(
            "GCP Vertex AI",
            "n1-standard-4 with Confidential VMs",
            model,
            batch_size,
            pricing,
        )
    }
}

// ============================================================================
// The AI Gas Profiler
// ============================================================================

/// The AI Gas Profiler - estimates costs before execution
pub struct AIGasProfiler {
    /// Current AETHEL to USD rate
    aethel_usd_rate: f64,
    /// Hardware-specific pricing
    hardware_pricing: HashMap<String, HardwarePricing>,
    /// zkML proof cost per MFLOP
    zkml_cost_per_mflop: f64,
    /// TEE attestation cost
    tee_attestation_cost: f64,
    /// Storage cost per KB
    storage_cost_per_kb: f64,
    /// Network cost per MB
    network_cost_per_mb: f64,
    /// Cloud provider pricing table (updatable)
    cloud_pricing: CloudPricingConfig,
}

/// Hardware-specific pricing
#[derive(Debug, Clone)]
pub struct HardwarePricing {
    /// Cost per TFLOP
    pub cost_per_tflop: f64,
    /// TEE overhead multiplier
    pub tee_overhead: f64,
    /// Power consumption (watts)
    pub power_watts: f64,
}

impl Default for AIGasProfiler {
    fn default() -> Self {
        let mut hardware_pricing = HashMap::new();

        hardware_pricing.insert(
            "generic_cpu".to_string(),
            HardwarePricing {
                cost_per_tflop: 0.01,
                tee_overhead: 0.0,
                power_watts: 100.0,
            },
        );

        hardware_pricing.insert(
            "intel_sgx".to_string(),
            HardwarePricing {
                cost_per_tflop: 0.015,
                tee_overhead: 0.3,
                power_watts: 120.0,
            },
        );

        hardware_pricing.insert(
            "amd_sev".to_string(),
            HardwarePricing {
                cost_per_tflop: 0.012,
                tee_overhead: 0.2,
                power_watts: 110.0,
            },
        );

        hardware_pricing.insert(
            "nvidia_h100".to_string(),
            HardwarePricing {
                cost_per_tflop: 0.002,
                tee_overhead: 0.1,
                power_watts: 700.0,
            },
        );

        hardware_pricing.insert(
            "nvidia_a100".to_string(),
            HardwarePricing {
                cost_per_tflop: 0.003,
                tee_overhead: 0.15,
                power_watts: 400.0,
            },
        );

        AIGasProfiler {
            aethel_usd_rate: 1.0, // 1 AETHEL = $1 USD
            hardware_pricing,
            zkml_cost_per_mflop: 0.0001,
            tee_attestation_cost: 0.1,
            storage_cost_per_kb: 0.0001,
            network_cost_per_mb: 0.001,
            cloud_pricing: CloudPricingConfig::default(),
        }
    }
}

impl AIGasProfiler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a profiler and optionally load cloud pricing from environment
    /// variables (`AETHELRED_SANDBOX_CLOUD_PRICING_FILE` then JSON fallback).
    pub fn try_new_from_env() -> Result<Self, String> {
        let mut profiler = Self::new();
        if let Some(pricing) = CloudPricingConfig::from_env()? {
            profiler.cloud_pricing = pricing;
        }
        Ok(profiler)
    }

    /// Override cloud pricing in-memory.
    pub fn set_cloud_pricing(&mut self, cloud_pricing: CloudPricingConfig) {
        self.cloud_pricing = cloud_pricing;
    }

    /// Parse and apply cloud pricing JSON.
    pub fn update_cloud_pricing_from_json(
        &mut self,
        config_json: &str,
    ) -> Result<(), serde_json::Error> {
        self.cloud_pricing = CloudPricingConfig::from_json(config_json)?;
        Ok(())
    }

    /// Inspect active cloud pricing.
    pub fn cloud_pricing(&self) -> &CloudPricingConfig {
        &self.cloud_pricing
    }

    /// Estimate cost for a model on specific hardware
    pub fn estimate(
        &self,
        model: &ModelSpec,
        hardware: &HardwareTarget,
        batch_size: u32,
    ) -> CostEstimate {
        let hardware_key = self.hardware_key(hardware);
        let pricing = self
            .hardware_pricing
            .get(&hardware_key)
            .unwrap_or_else(|| self.hardware_pricing.get("generic_cpu").unwrap());

        // Calculate FLOPs
        let total_flops = model.flops_per_inference * batch_size as u64;
        let tflops = total_flops as f64 / 1_000_000_000_000.0;

        // Compute cost
        let compute_cost = tflops * pricing.cost_per_tflop;

        // TEE overhead
        let tee_cost = if model.requires_tee {
            compute_cost * pricing.tee_overhead + self.tee_attestation_cost
        } else {
            0.0
        };

        // Proof generation cost
        let proof_cost = if model.requires_zkml {
            (total_flops as f64 / 1_000_000.0) * self.zkml_cost_per_mflop
        } else {
            0.0
        };

        // Storage cost
        let output_size_kb = model.output_dims.iter().product::<u32>() * batch_size * 4 / 1024;
        let storage_cost = output_size_kb as f64 * self.storage_cost_per_kb;

        // Network cost (input transfer)
        let input_size_mb =
            (model.input_dims.iter().product::<u32>() * batch_size * 4) as f64 / 1_000_000.0;
        let network_cost = input_size_mb * self.network_cost_per_mb;

        // Total
        let total_aethel = compute_cost + tee_cost + proof_cost + storage_cost + network_cost;
        let total_usd = total_aethel * self.aethel_usd_rate;

        // Create breakdown
        let breakdown = GasCostBreakdown {
            compute: CostComponent {
                aethel: compute_cost,
                percentage: compute_cost / total_aethel * 100.0,
                description: format!("{:.2} TFLOPs compute", tflops),
            },
            tee_overhead: CostComponent {
                aethel: tee_cost,
                percentage: tee_cost / total_aethel * 100.0,
                description: "TEE enclave + attestation".to_string(),
            },
            proof_generation: CostComponent {
                aethel: proof_cost,
                percentage: proof_cost / total_aethel * 100.0,
                description: "zkML proof generation".to_string(),
            },
            storage: CostComponent {
                aethel: storage_cost,
                percentage: storage_cost / total_aethel * 100.0,
                description: format!("{} KB result storage", output_size_kb),
            },
            network: CostComponent {
                aethel: network_cost,
                percentage: network_cost / total_aethel * 100.0,
                description: format!("{:.2} MB data transfer", input_size_mb),
            },
            total_aethel,
            total_usd,
        };

        // Calculate execution time
        let tflops_per_second = match hardware_key.as_str() {
            "nvidia_h100" => 1000.0, // 1 PFLOP/s
            "nvidia_a100" => 300.0,  // 300 TFLOP/s
            "intel_sgx" => 0.5,      // ~0.5 TFLOP/s
            "amd_sev" => 1.0,        // ~1 TFLOP/s
            _ => 0.1,                // Generic CPU
        };

        let execution_time_secs = tflops / tflops_per_second;

        // Environmental impact
        let energy_wh = execution_time_secs / 3600.0 * pricing.power_watts;
        let location = hardware.data_location().unwrap_or("AE");
        let environmental_impact = EnvironmentalImpact::from_energy(energy_wh, location);

        // Cloud comparisons
        let aws = CloudPricing::estimate_aws_sagemaker(
            model,
            batch_size,
            &self.cloud_pricing.aws_sagemaker,
        );
        let azure =
            CloudPricing::estimate_azure_ml(model, batch_size, &self.cloud_pricing.azure_ml);
        let gcp =
            CloudPricing::estimate_gcp_vertex(model, batch_size, &self.cloud_pricing.gcp_vertex);

        let cloud_comparisons = vec![
            CloudComparison {
                cost_ratio: aws.cost_usd / total_usd,
                ..aws
            },
            CloudComparison {
                cost_ratio: azure.cost_usd / total_usd,
                ..azure
            },
            CloudComparison {
                cost_ratio: gcp.cost_usd / total_usd,
                ..gcp
            },
        ];

        CostEstimate {
            model: model.clone(),
            hardware: hardware.clone(),
            batch_size,
            breakdown,
            execution_time_secs,
            environmental_impact,
            cloud_comparisons,
        }
    }

    fn hardware_key(&self, hardware: &HardwareTarget) -> String {
        match hardware {
            HardwareTarget::GenericCPU => "generic_cpu".to_string(),
            HardwareTarget::IntelSGX { .. } => "intel_sgx".to_string(),
            HardwareTarget::AMDSEV { .. } => "amd_sev".to_string(),
            HardwareTarget::AWSNitro { .. } => "intel_sgx".to_string(), // Similar to SGX
            HardwareTarget::NvidiaH100 { .. } => "nvidia_h100".to_string(),
            HardwareTarget::NvidiaA100 { .. } => "nvidia_a100".to_string(),
            HardwareTarget::Simulated { simulates } => self.hardware_key(simulates),
        }
    }

    /// Generate a visual report
    pub fn generate_report(&self, estimate: &CostEstimate) -> String {
        let breakdown = &estimate.breakdown;
        let env = &estimate.environmental_impact;

        let compute_bar = Self::progress_bar(breakdown.compute.percentage, 30);
        let tee_bar = Self::progress_bar(breakdown.tee_overhead.percentage, 30);
        let proof_bar = Self::progress_bar(breakdown.proof_generation.percentage, 30);
        let storage_bar = Self::progress_bar(breakdown.storage.percentage, 30);
        let network_bar = Self::progress_bar(breakdown.network.percentage, 30);

        let mut report = format!(
            r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        💰 AI GAS PROFILER                                     ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  MODEL:    {}
║  HARDWARE: {}
║  BATCH:    {} items
║  TIME:     {:.2}s estimated
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  COST BREAKDOWN                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  COMPUTE       {} {:>8.3} AETHEL ({:.1}%)
║  TEE OVERHEAD  {} {:>8.3} AETHEL ({:.1}%)
║  PROOF GEN     {} {:>8.3} AETHEL ({:.1}%)
║  STORAGE       {} {:>8.3} AETHEL ({:.1}%)
║  NETWORK       {} {:>8.3} AETHEL ({:.1}%)
║  ──────────────────────────────────────────────────────────────────────────── ║
║  TOTAL                                       {:>8.3} AETHEL (${:.2} USD)
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  🌍 ENVIRONMENTAL IMPACT                                                      ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  ⚡ Energy:       {:>8.2} Wh
║  🌍 Carbon:       {:>8.4} kg CO2
║  💧 Water:        {:>8.2} liters
║  🌳 Tree offset:  {:>8.4} trees/year
║                                                                               ║
║  Comparison: {}
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  ☁️  CLOUD COMPARISON                                                          ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
"#,
            estimate.model.name,
            estimate.hardware.display_name(),
            estimate.batch_size,
            estimate.execution_time_secs,
            compute_bar,
            breakdown.compute.aethel,
            breakdown.compute.percentage,
            tee_bar,
            breakdown.tee_overhead.aethel,
            breakdown.tee_overhead.percentage,
            proof_bar,
            breakdown.proof_generation.aethel,
            breakdown.proof_generation.percentage,
            storage_bar,
            breakdown.storage.aethel,
            breakdown.storage.percentage,
            network_bar,
            breakdown.network.aethel,
            breakdown.network.percentage,
            breakdown.total_aethel,
            breakdown.total_usd,
            env.energy_wh,
            env.carbon_kg,
            env.water_liters,
            env.trees_per_year,
            env.comparison,
        );

        for comparison in &estimate.cloud_comparisons {
            let status = if comparison.cost_ratio > 1.0 {
                format!("({:.1}x more expensive)", comparison.cost_ratio)
            } else {
                format!("({:.1}x cheaper)", 1.0 / comparison.cost_ratio)
            };
            report.push_str(&format!(
                "║  {:20} ${:>8.2}  {}\n",
                comparison.provider, comparison.cost_usd, status
            ));
        }

        report.push_str(&format!(
            "║  {:20} {:>8.3} AETHEL ≈ ${:.2}  ✅ VERIFIED + SOVEREIGN\n",
            "Aethelred", breakdown.total_aethel, breakdown.total_usd
        ));

        report.push_str(
            r#"║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  💡 AETHELRED ADVANTAGES                                                      ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  ✅ Cryptographic proof of computation (zkML + TEE)                          ║
║  ✅ Data sovereignty guaranteed (UAE jurisdiction)                            ║
║  ✅ Immutable audit trail (Digital Seal)                                      ║
║  ✅ No vendor lock-in (decentralized validators)                              ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#,
        );

        report
    }

    fn progress_bar(percentage: f64, width: usize) -> String {
        let filled = ((percentage / 100.0) * width as f64) as usize;
        let empty = width.saturating_sub(filled);
        format!("{}{}", "█".repeat(filled), "░".repeat(empty))
    }

    /// Quick estimate for display
    pub fn quick_estimate(model_type: &str, batch_size: u32) -> String {
        let profiler = AIGasProfiler::new();

        let model = match model_type {
            "credit_scoring" => ModelSpec::credit_scoring(),
            "fraud_detection" => ModelSpec::fraud_detection(),
            "llm" => ModelSpec::llm_inference(),
            _ => ModelSpec::credit_scoring(),
        };

        let hardware = HardwareTarget::IntelSGX {
            location: crate::core::DataCenterLocation {
                country: "AE".to_string(),
                city: "Abu Dhabi".to_string(),
                provider: crate::core::CloudProvider::Aethelred,
                dc_id: Some("AD-01".to_string()),
            },
            svn: 15,
        };

        let estimate = profiler.estimate(&model, &hardware, batch_size);

        format!(
            "{:.2} AETHEL | {:.2} Wh | {:.3} kg CO2",
            estimate.breakdown.total_aethel,
            estimate.environmental_impact.energy_wh,
            estimate.environmental_impact.carbon_kg
        )
    }
}

/// Complete cost estimate
#[derive(Debug, Clone)]
pub struct CostEstimate {
    /// Model specification
    pub model: ModelSpec,
    /// Hardware target
    pub hardware: HardwareTarget,
    /// Batch size
    pub batch_size: u32,
    /// Cost breakdown
    pub breakdown: GasCostBreakdown,
    /// Estimated execution time
    pub execution_time_secs: f64,
    /// Environmental impact
    pub environmental_impact: EnvironmentalImpact,
    /// Cloud comparisons
    pub cloud_comparisons: Vec<CloudComparison>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{CloudProvider, DataCenterLocation};
    use std::sync::{Mutex, OnceLock};

    #[test]
    fn test_credit_scoring_estimate() {
        let profiler = AIGasProfiler::new();
        let model = ModelSpec::credit_scoring();
        let hardware = HardwareTarget::IntelSGX {
            location: DataCenterLocation {
                country: "AE".to_string(),
                city: "Abu Dhabi".to_string(),
                provider: CloudProvider::Aethelred,
                dc_id: Some("AD-01".to_string()),
            },
            svn: 15,
        };

        let estimate = profiler.estimate(&model, &hardware, 1000);

        assert!(estimate.breakdown.total_aethel > 0.0);
        assert!(estimate.environmental_impact.energy_wh > 0.0);
        assert!(estimate.cloud_comparisons.len() == 3);
    }

    #[test]
    fn test_gpu_cheaper_than_cpu() {
        let profiler = AIGasProfiler::new();
        let model = ModelSpec::fraud_detection();

        let sgx = HardwareTarget::IntelSGX {
            location: DataCenterLocation {
                country: "AE".to_string(),
                city: "Abu Dhabi".to_string(),
                provider: CloudProvider::Aethelred,
                dc_id: None,
            },
            svn: 15,
        };

        let h100 = HardwareTarget::NvidiaH100 {
            location: DataCenterLocation {
                country: "SG".to_string(),
                city: "Singapore".to_string(),
                provider: CloudProvider::AWS,
                dc_id: None,
            },
            gpu_count: 1,
        };

        let sgx_estimate = profiler.estimate(&model, &sgx, 1000);
        let h100_estimate = profiler.estimate(&model, &h100, 1000);

        // H100 should have lower compute cost per TFLOP
        assert!(h100_estimate.breakdown.compute.aethel < sgx_estimate.breakdown.compute.aethel);
    }

    #[test]
    fn test_environmental_impact() {
        let impact = EnvironmentalImpact::from_energy(1000.0, "AE");

        assert!(impact.carbon_kg > 0.0);
        assert!(impact.water_liters > 0.0);
        assert!(impact.trees_per_year > 0.0);
    }

    #[test]
    fn test_cloud_pricing_is_updatable_from_json() {
        let mut profiler = AIGasProfiler::new();
        let model = ModelSpec::credit_scoring();
        let hardware = HardwareTarget::GenericCPU;

        let baseline = profiler.estimate(&model, &hardware, 1000);
        let baseline_aws = baseline
            .cloud_comparisons
            .iter()
            .find(|c| c.provider == "AWS SageMaker")
            .expect("missing AWS comparison")
            .cost_usd;

        let pricing_json = r#"{
            "aws_sagemaker": {
                "tree_based_cost_per_100": 0.50,
                "neural_network_cost_per_100": 0.75,
                "transformer_cost_per_100": 1.50,
                "default_cost_per_100": 0.50,
                "tee_overhead_multiplier": 0.30
            },
            "azure_ml": {
                "tree_based_cost_per_100": 0.012,
                "neural_network_cost_per_100": 0.022,
                "transformer_cost_per_100": 0.55,
                "default_cost_per_100": 0.012,
                "tee_overhead_multiplier": 0.0
            },
            "gcp_vertex": {
                "tree_based_cost_per_100": 0.009,
                "neural_network_cost_per_100": 0.018,
                "transformer_cost_per_100": 0.45,
                "default_cost_per_100": 0.009,
                "tee_overhead_multiplier": 0.0
            }
        }"#;

        profiler
            .update_cloud_pricing_from_json(pricing_json)
            .expect("cloud pricing update failed");
        let updated = profiler.estimate(&model, &hardware, 1000);
        let updated_aws = updated
            .cloud_comparisons
            .iter()
            .find(|c| c.provider == "AWS SageMaker")
            .expect("missing AWS comparison")
            .cost_usd;

        assert!(updated_aws > baseline_aws);
    }

    #[test]
    fn test_cloud_pricing_can_load_from_file() {
        let mut file_path = std::env::temp_dir();
        file_path.push(format!(
            "aethelred_cloud_pricing_{}_{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be monotonic")
                .as_nanos()
        ));

        let file_json = r#"{
            "aws_sagemaker": {
                "tree_based_cost_per_100": 0.91,
                "neural_network_cost_per_100": 0.91,
                "transformer_cost_per_100": 0.91,
                "default_cost_per_100": 0.91,
                "tee_overhead_multiplier": 0.0
            },
            "azure_ml": {
                "tree_based_cost_per_100": 0.012,
                "neural_network_cost_per_100": 0.022,
                "transformer_cost_per_100": 0.55,
                "default_cost_per_100": 0.012,
                "tee_overhead_multiplier": 0.0
            },
            "gcp_vertex": {
                "tree_based_cost_per_100": 0.009,
                "neural_network_cost_per_100": 0.018,
                "transformer_cost_per_100": 0.45,
                "default_cost_per_100": 0.009,
                "tee_overhead_multiplier": 0.0
            }
        }"#;

        std::fs::write(&file_path, file_json).expect("pricing file write should succeed");
        let pricing = CloudPricingConfig::from_file(file_path.to_str().expect("utf8 path"))
            .expect("file config should parse");
        assert!((pricing.aws_sagemaker.tree_based_cost_per_100 - 0.91).abs() < 1e-9);

        let _ = std::fs::remove_file(file_path);
    }

    #[test]
    fn test_try_new_from_env_prefers_file_over_json() {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = ENV_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock.lock().expect("env lock poisoned");

        let mut file_path = std::env::temp_dir();
        file_path.push(format!(
            "aethelred_cloud_pricing_env_{}_{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be monotonic")
                .as_nanos()
        ));

        let file_json = r#"{
            "aws_sagemaker": {
                "tree_based_cost_per_100": 0.77,
                "neural_network_cost_per_100": 0.77,
                "transformer_cost_per_100": 0.77,
                "default_cost_per_100": 0.77,
                "tee_overhead_multiplier": 0.0
            },
            "azure_ml": {
                "tree_based_cost_per_100": 0.012,
                "neural_network_cost_per_100": 0.022,
                "transformer_cost_per_100": 0.55,
                "default_cost_per_100": 0.012,
                "tee_overhead_multiplier": 0.0
            },
            "gcp_vertex": {
                "tree_based_cost_per_100": 0.009,
                "neural_network_cost_per_100": 0.018,
                "transformer_cost_per_100": 0.45,
                "default_cost_per_100": 0.009,
                "tee_overhead_multiplier": 0.0
            }
        }"#;
        std::fs::write(&file_path, file_json).expect("pricing file write should succeed");

        std::env::set_var(
            CLOUD_PRICING_JSON_ENV,
            r#"{
                "aws_sagemaker": {
                    "tree_based_cost_per_100": 0.33,
                    "neural_network_cost_per_100": 0.33,
                    "transformer_cost_per_100": 0.33,
                    "default_cost_per_100": 0.33,
                    "tee_overhead_multiplier": 0.0
                },
                "azure_ml": {
                    "tree_based_cost_per_100": 0.012,
                    "neural_network_cost_per_100": 0.022,
                    "transformer_cost_per_100": 0.55,
                    "default_cost_per_100": 0.012,
                    "tee_overhead_multiplier": 0.0
                },
                "gcp_vertex": {
                    "tree_based_cost_per_100": 0.009,
                    "neural_network_cost_per_100": 0.018,
                    "transformer_cost_per_100": 0.45,
                    "default_cost_per_100": 0.009,
                    "tee_overhead_multiplier": 0.0
                }
            }"#,
        );
        std::env::set_var(
            CLOUD_PRICING_FILE_ENV,
            file_path.to_str().expect("utf8 path"),
        );

        let profiler = AIGasProfiler::try_new_from_env().expect("env config should parse");
        let estimate = profiler.estimate(
            &ModelSpec::credit_scoring(),
            &HardwareTarget::GenericCPU,
            100,
        );
        let aws = estimate
            .cloud_comparisons
            .iter()
            .find(|c| c.provider == "AWS SageMaker")
            .expect("aws comparison missing");
        assert!((aws.cost_usd - 0.77).abs() < 1e-9);

        std::env::remove_var(CLOUD_PRICING_FILE_ENV);
        std::env::remove_var(CLOUD_PRICING_JSON_ENV);
        let _ = std::fs::remove_file(file_path);
    }
}
