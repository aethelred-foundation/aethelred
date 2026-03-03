//! # Hardware-Aware Runtime
//!
//! **"The First Dropdown That Matters"**
//!
//! This module provides the hardware selection interface. Users choose
//! their execution target and the sandbox simulates the exact
//! performance characteristics.
//!
//! ## Hardware Selection
//!
//! ```text
//! ╔═══════════════════════════════════════════════════════════════════════════════╗
//! ║                        🖥️  HARDWARE-AWARE RUNTIME                             ║
//! ╠═══════════════════════════════════════════════════════════════════════════════╣
//! ║                                                                               ║
//! ║  SELECT EXECUTION TARGET                                                      ║
//! ║                                                                               ║
//! ║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
//! ║  │                                                                         │ ║
//! ║  │  ○ Generic CPU                                                          │ ║
//! ║  │    No TEE, fastest for prototyping                                      │ ║
//! ║  │    └─ Est. speed: 0.1 TFLOP/s | Cost: 0.01 AETHEL/TFLOP                │ ║
//! ║  │                                                                         │ ║
//! ║  │  ● Intel SGX (Abu Dhabi) ✓ RECOMMENDED                                  │ ║
//! ║  │    Full TEE, GDPR compliant, UAE data sovereignty                       │ ║
//! ║  │    └─ Est. speed: 0.5 TFLOP/s | Cost: 0.015 AETHEL/TFLOP               │ ║
//! ║  │                                                                         │ ║
//! ║  │  ○ AMD SEV (Dubai)                                                      │ ║
//! ║  │    Memory encryption, lower overhead                                    │ ║
//! ║  │    └─ Est. speed: 1.0 TFLOP/s | Cost: 0.012 AETHEL/TFLOP               │ ║
//! ║  │                                                                         │ ║
//! ║  │  ○ AWS Nitro (me-south-1)                                              │ ║
//! ║  │    Cloud TEE, easy deployment                                           │ ║
//! ║  │    └─ Est. speed: 0.8 TFLOP/s | Cost: 0.014 AETHEL/TFLOP               │ ║
//! ║  │                                                                         │ ║
//! ║  │  ○ NVIDIA H100 (Singapore)                                              │ ║
//! ║  │    GPU TEE, best for large models                                       │ ║
//! ║  │    └─ Est. speed: 1000 TFLOP/s | Cost: 0.002 AETHEL/TFLOP              │ ║
//! ║  │                                                                         │ ║
//! ║  └─────────────────────────────────────────────────────────────────────────┘ ║
//! ║                                                                               ║
//! ╚═══════════════════════════════════════════════════════════════════════════════╝
//! ```

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::core::{CloudProvider, DataCenterLocation, HardwareTarget};

// ============================================================================
// Hardware Specifications
// ============================================================================

/// Detailed hardware specifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareSpec {
    /// Hardware target
    pub target: HardwareTarget,
    /// Display name
    pub display_name: String,
    /// Description
    pub description: String,
    /// Performance in TFLOP/s
    pub tflops: f64,
    /// Cost per TFLOP in AETHEL
    pub cost_per_tflop: f64,
    /// TEE type (if any)
    pub tee_type: Option<TEESpec>,
    /// Memory available (GB)
    pub memory_gb: u32,
    /// Power consumption (Watts)
    pub power_watts: u32,
    /// Certifications
    pub certifications: Vec<Certification>,
    /// Status
    pub status: HardwareStatus,
    /// Load percentage (0-100)
    pub current_load: u8,
}

/// TEE specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEESpec {
    /// TEE technology
    pub technology: TEETechnology,
    /// Enclave memory limit
    pub enclave_memory_mb: u32,
    /// Attestation type
    pub attestation: AttestationType,
    /// Sealing supported
    pub sealing_supported: bool,
    /// Remote attestation supported
    pub remote_attestation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TEETechnology {
    IntelSGX1,
    IntelSGX2,
    IntelTDX,
    AMDSEV,
    AMDSEVSnp,
    AWSNitro,
    ARMTrustZone,
    NvidiaCCMode,
}

impl TEETechnology {
    pub fn display_name(&self) -> &'static str {
        match self {
            TEETechnology::IntelSGX1 => "Intel SGX1",
            TEETechnology::IntelSGX2 => "Intel SGX2",
            TEETechnology::IntelTDX => "Intel TDX",
            TEETechnology::AMDSEV => "AMD SEV",
            TEETechnology::AMDSEVSnp => "AMD SEV-SNP",
            TEETechnology::AWSNitro => "AWS Nitro Enclaves",
            TEETechnology::ARMTrustZone => "ARM TrustZone",
            TEETechnology::NvidiaCCMode => "NVIDIA Confidential Computing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationType {
    /// Intel EPID attestation
    EPID,
    /// Intel DCAP attestation
    DCAP,
    /// AMD attestation
    AMDCert,
    /// AWS attestation
    AWSAttestation,
    /// NVIDIA attestation
    NvidiaAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Certification {
    SOC2Type2,
    ISO27001,
    HIPAA,
    PCIDSS,
    FedRAMPHigh,
    GDPR,
    UAEDataSovereignty,
    DIFC,
    MASOutsourcing,
}

impl Certification {
    pub fn display_name(&self) -> &'static str {
        match self {
            Certification::SOC2Type2 => "SOC2 Type II",
            Certification::ISO27001 => "ISO 27001",
            Certification::HIPAA => "HIPAA",
            Certification::PCIDSS => "PCI-DSS",
            Certification::FedRAMPHigh => "FedRAMP High",
            Certification::GDPR => "GDPR Compliant",
            Certification::UAEDataSovereignty => "UAE Data Sovereignty",
            Certification::DIFC => "DIFC Certified",
            Certification::MASOutsourcing => "MAS Outsourcing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareStatus {
    Online,
    Degraded,
    Maintenance,
    Offline,
}

// ============================================================================
// Execution Simulation
// ============================================================================

/// Simulated execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Execution ID
    pub id: String,
    /// Hardware used
    pub hardware: HardwareTarget,
    /// Execution time
    pub execution_time: Duration,
    /// TEE attestation (if applicable)
    pub attestation: Option<SimulatedAttestation>,
    /// Resource usage
    pub resource_usage: ResourceUsage,
    /// Cost
    pub cost_aethel: f64,
    /// Output hash
    pub output_hash: [u8; 32],
    /// Status
    pub status: ExecutionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedAttestation {
    /// Quote bytes (simulated)
    pub quote: Vec<u8>,
    /// Measurement (MRENCLAVE for SGX)
    pub measurement: [u8; 32],
    /// Signer (MRSIGNER for SGX)
    pub signer: [u8; 32],
    /// Product ID
    pub product_id: u16,
    /// Security version
    pub security_version: u16,
    /// Report data
    pub report_data: Vec<u8>,
    /// Verification timestamp
    pub verified_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// CPU time (ms)
    pub cpu_time_ms: u64,
    /// Memory peak (MB)
    pub memory_peak_mb: u64,
    /// Enclave memory (MB) if TEE
    pub enclave_memory_mb: Option<u64>,
    /// Network bytes
    pub network_bytes: u64,
    /// Storage bytes written
    pub storage_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed { error: String },
    Timeout,
}

// ============================================================================
// Hardware-Aware Runtime
// ============================================================================

/// The Hardware-Aware Runtime manager
pub struct HardwareRuntime {
    /// Available hardware targets
    hardware_catalog: Vec<HardwareSpec>,
    /// Currently selected target
    selected_target: Option<HardwareTarget>,
    /// Execution history
    execution_history: Vec<ExecutionResult>,
}

impl HardwareRuntime {
    pub fn new() -> Self {
        let catalog = Self::initialize_catalog();

        HardwareRuntime {
            hardware_catalog: catalog,
            selected_target: None,
            execution_history: Vec::new(),
        }
    }

    fn initialize_catalog() -> Vec<HardwareSpec> {
        vec![
            // Generic CPU
            HardwareSpec {
                target: HardwareTarget::GenericCPU,
                display_name: "Generic CPU".to_string(),
                description: "No TEE, fastest for prototyping".to_string(),
                tflops: 0.1,
                cost_per_tflop: 0.01,
                tee_type: None,
                memory_gb: 32,
                power_watts: 100,
                certifications: vec![],
                status: HardwareStatus::Online,
                current_load: 20,
            },
            // Intel SGX (Abu Dhabi)
            HardwareSpec {
                target: HardwareTarget::IntelSGX {
                    location: DataCenterLocation {
                        country: "AE".to_string(),
                        city: "Abu Dhabi".to_string(),
                        provider: CloudProvider::Aethelred,
                        dc_id: Some("AD-01".to_string()),
                    },
                    svn: 15,
                },
                display_name: "Intel SGX (Abu Dhabi)".to_string(),
                description: "Full TEE, GDPR compliant, UAE data sovereignty".to_string(),
                tflops: 0.5,
                cost_per_tflop: 0.015,
                tee_type: Some(TEESpec {
                    technology: TEETechnology::IntelSGX2,
                    enclave_memory_mb: 256,
                    attestation: AttestationType::DCAP,
                    sealing_supported: true,
                    remote_attestation: true,
                }),
                memory_gb: 64,
                power_watts: 120,
                certifications: vec![
                    Certification::SOC2Type2,
                    Certification::ISO27001,
                    Certification::UAEDataSovereignty,
                    Certification::DIFC,
                ],
                status: HardwareStatus::Online,
                current_load: 45,
            },
            // AMD SEV (Dubai)
            HardwareSpec {
                target: HardwareTarget::AMDSEV {
                    location: DataCenterLocation {
                        country: "AE".to_string(),
                        city: "Dubai".to_string(),
                        provider: CloudProvider::Aethelred,
                        dc_id: Some("DXB-01".to_string()),
                    },
                    variant: "SEV-SNP".to_string(),
                },
                display_name: "AMD SEV (Dubai)".to_string(),
                description: "Memory encryption, lower overhead".to_string(),
                tflops: 1.0,
                cost_per_tflop: 0.012,
                tee_type: Some(TEESpec {
                    technology: TEETechnology::AMDSEVSnp,
                    enclave_memory_mb: 4096, // Full VM memory
                    attestation: AttestationType::AMDCert,
                    sealing_supported: true,
                    remote_attestation: true,
                }),
                memory_gb: 128,
                power_watts: 110,
                certifications: vec![Certification::SOC2Type2, Certification::UAEDataSovereignty],
                status: HardwareStatus::Online,
                current_load: 35,
            },
            // AWS Nitro
            HardwareSpec {
                target: HardwareTarget::AWSNitro {
                    region: "me-south-1".to_string(),
                },
                display_name: "AWS Nitro (Bahrain)".to_string(),
                description: "Cloud TEE, easy deployment".to_string(),
                tflops: 0.8,
                cost_per_tflop: 0.014,
                tee_type: Some(TEESpec {
                    technology: TEETechnology::AWSNitro,
                    enclave_memory_mb: 8192,
                    attestation: AttestationType::AWSAttestation,
                    sealing_supported: false,
                    remote_attestation: true,
                }),
                memory_gb: 64,
                power_watts: 150,
                certifications: vec![
                    Certification::SOC2Type2,
                    Certification::ISO27001,
                    Certification::HIPAA,
                    Certification::PCIDSS,
                ],
                status: HardwareStatus::Online,
                current_load: 62,
            },
            // NVIDIA H100 (Singapore)
            HardwareSpec {
                target: HardwareTarget::NvidiaH100 {
                    location: DataCenterLocation {
                        country: "SG".to_string(),
                        city: "Singapore".to_string(),
                        provider: CloudProvider::AWS,
                        dc_id: None,
                    },
                    gpu_count: 8,
                },
                display_name: "8x NVIDIA H100 (Singapore)".to_string(),
                description: "GPU TEE, best for large models".to_string(),
                tflops: 1000.0, // 8 GPUs
                cost_per_tflop: 0.002,
                tee_type: Some(TEESpec {
                    technology: TEETechnology::NvidiaCCMode,
                    enclave_memory_mb: 80 * 1024 * 8, // 80GB per GPU
                    attestation: AttestationType::NvidiaAttestation,
                    sealing_supported: false,
                    remote_attestation: true,
                }),
                memory_gb: 80 * 8,    // 640GB GPU memory
                power_watts: 700 * 8, // 5.6kW
                certifications: vec![Certification::SOC2Type2, Certification::MASOutsourcing],
                status: HardwareStatus::Online,
                current_load: 78,
            },
            // NVIDIA A100 (UAE)
            HardwareSpec {
                target: HardwareTarget::NvidiaA100 {
                    location: DataCenterLocation {
                        country: "AE".to_string(),
                        city: "Abu Dhabi".to_string(),
                        provider: CloudProvider::Aethelred,
                        dc_id: Some("AD-GPU-01".to_string()),
                    },
                    gpu_count: 4,
                },
                display_name: "4x NVIDIA A100 (Abu Dhabi)".to_string(),
                description: "GPU compute, UAE data sovereignty".to_string(),
                tflops: 300.0, // 4 GPUs
                cost_per_tflop: 0.003,
                tee_type: None,       // A100 doesn't have CC mode like H100
                memory_gb: 40 * 4,    // 160GB GPU memory
                power_watts: 400 * 4, // 1.6kW
                certifications: vec![Certification::SOC2Type2, Certification::UAEDataSovereignty],
                status: HardwareStatus::Online,
                current_load: 55,
            },
        ]
    }

    /// Get available hardware targets
    pub fn get_available_hardware(&self) -> Vec<&HardwareSpec> {
        self.hardware_catalog
            .iter()
            .filter(|h| h.status == HardwareStatus::Online)
            .collect()
    }

    /// Select a hardware target
    pub fn select_target(&mut self, target: HardwareTarget) -> Result<(), RuntimeError> {
        let spec = self
            .hardware_catalog
            .iter()
            .find(|h| std::mem::discriminant(&h.target) == std::mem::discriminant(&target));

        if let Some(spec) = spec {
            if spec.status != HardwareStatus::Online {
                return Err(RuntimeError::HardwareNotAvailable);
            }
            self.selected_target = Some(target);
            Ok(())
        } else {
            Err(RuntimeError::HardwareNotFound)
        }
    }

    /// Simulate execution on selected hardware
    pub fn simulate_execution(
        &mut self,
        workload_tflops: f64,
        requires_tee: bool,
    ) -> Result<ExecutionResult, RuntimeError> {
        let target = self
            .selected_target
            .clone()
            .ok_or(RuntimeError::NoTargetSelected)?;

        let spec = self
            .hardware_catalog
            .iter()
            .find(|h| std::mem::discriminant(&h.target) == std::mem::discriminant(&target))
            .ok_or(RuntimeError::HardwareNotFound)?;

        if requires_tee && spec.tee_type.is_none() {
            return Err(RuntimeError::TEERequired);
        }

        // Calculate execution time
        let execution_time_secs = workload_tflops / spec.tflops;
        let execution_time = Duration::from_secs_f64(execution_time_secs);

        // Calculate cost
        let cost_aethel = workload_tflops * spec.cost_per_tflop;

        // Generate attestation if TEE
        let attestation = spec.tee_type.as_ref().map(|_| SimulatedAttestation {
            quote: vec![0u8; 1024],
            measurement: [0u8; 32],
            signer: [0u8; 32],
            product_id: 1,
            security_version: 15,
            report_data: vec![0u8; 64],
            verified_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });

        let result = ExecutionResult {
            id: format!("exec-{}", uuid::Uuid::new_v4()),
            hardware: target,
            execution_time,
            attestation,
            resource_usage: ResourceUsage {
                cpu_time_ms: (execution_time_secs * 1000.0) as u64,
                memory_peak_mb: (workload_tflops * 10.0) as u64,
                enclave_memory_mb: spec.tee_type.as_ref().map(|t| t.enclave_memory_mb as u64),
                network_bytes: 0,
                storage_bytes: 0,
            },
            cost_aethel,
            output_hash: [0u8; 32],
            status: ExecutionStatus::Completed,
        };

        self.execution_history.push(result.clone());
        Ok(result)
    }

    /// Generate hardware selection UI
    pub fn generate_selection_ui(&self) -> String {
        let mut ui = String::new();

        ui.push_str(
            r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        🖥️  HARDWARE-AWARE RUNTIME                             ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  SELECT EXECUTION TARGET                                                      ║
║                                                                               ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
"#,
        );

        for spec in &self.hardware_catalog {
            let selected = self
                .selected_target
                .as_ref()
                .map(|t| std::mem::discriminant(t) == std::mem::discriminant(&spec.target))
                .unwrap_or(false);

            let marker = if selected { "●" } else { "○" };
            let recommended = if spec.tee_type.is_some()
                && spec
                    .certifications
                    .contains(&Certification::UAEDataSovereignty)
            {
                " ✓ RECOMMENDED"
            } else {
                ""
            };

            let status_icon = match spec.status {
                HardwareStatus::Online => "🟢",
                HardwareStatus::Degraded => "🟡",
                HardwareStatus::Maintenance => "🔧",
                HardwareStatus::Offline => "🔴",
            };

            ui.push_str(&format!(
                "║  │  {} {} {}{}                        │ ║\n",
                marker, spec.display_name, status_icon, recommended
            ));
            ui.push_str(&format!(
                "║  │    {}                            │ ║\n",
                spec.description
            ));
            ui.push_str(&format!(
                "║  │    └─ Est. speed: {} TFLOP/s | Cost: {} AETHEL/TFLOP    │ ║\n",
                spec.tflops, spec.cost_per_tflop
            ));

            if let Some(tee) = &spec.tee_type {
                ui.push_str(&format!(
                    "║  │       TEE: {} ({} MB enclave)              │ ║\n",
                    tee.technology.display_name(),
                    tee.enclave_memory_mb
                ));
            }

            if !spec.certifications.is_empty() {
                let certs: Vec<_> = spec
                    .certifications
                    .iter()
                    .take(3)
                    .map(|c| c.display_name())
                    .collect();
                ui.push_str(&format!(
                    "║  │       Certs: {}                              │ ║\n",
                    certs.join(", ")
                ));
            }

            ui.push_str("║  │                                                                         │ ║\n");
        }

        ui.push_str(
            r#"║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  QUICK COMPARISON                                                             ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  For Credit Scoring (1000 applications):                                      ║
║  ┌─────────────────────────────────────────────────────────────────────────┐ ║
║  │  Generic CPU:      ~100s  │ 0.1 AETHEL  │ No TEE                        │ ║
║  │  Intel SGX (AE):   ~20s   │ 0.3 AETHEL  │ Full TEE + UAE Sovereignty    │ ║
║  │  AMD SEV (AE):     ~10s   │ 0.24 AETHEL │ TEE + UAE Sovereignty         │ ║
║  │  NVIDIA H100 (SG): ~0.1s  │ 0.04 AETHEL │ GPU TEE (fastest)             │ ║
║  └─────────────────────────────────────────────────────────────────────────┘ ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#,
        );

        ui
    }

    /// Get currently selected target
    pub fn get_selected_target(&self) -> Option<&HardwareTarget> {
        self.selected_target.as_ref()
    }

    /// Get hardware spec by target
    pub fn get_spec(&self, target: &HardwareTarget) -> Option<&HardwareSpec> {
        self.hardware_catalog
            .iter()
            .find(|h| std::mem::discriminant(&h.target) == std::mem::discriminant(target))
    }
}

impl Default for HardwareRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub enum RuntimeError {
    HardwareNotFound,
    HardwareNotAvailable,
    NoTargetSelected,
    TEERequired,
    ExecutionFailed(String),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::HardwareNotFound => write!(f, "Hardware target not found"),
            RuntimeError::HardwareNotAvailable => write!(f, "Hardware target not available"),
            RuntimeError::NoTargetSelected => write!(f, "No hardware target selected"),
            RuntimeError::TEERequired => {
                write!(f, "TEE required but not available on selected hardware")
            }
            RuntimeError::ExecutionFailed(e) => write!(f, "Execution failed: {}", e),
        }
    }
}

impl std::error::Error for RuntimeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_selection() {
        let mut runtime = HardwareRuntime::new();

        assert!(runtime.selected_target.is_none());

        runtime.select_target(HardwareTarget::GenericCPU).unwrap();
        assert!(runtime.selected_target.is_some());
    }

    #[test]
    fn test_execution_simulation() {
        let mut runtime = HardwareRuntime::new();
        runtime.select_target(HardwareTarget::GenericCPU).unwrap();

        let result = runtime.simulate_execution(1.0, false).unwrap();

        assert_eq!(result.status, ExecutionStatus::Completed);
        assert!(result.cost_aethel > 0.0);
    }

    #[test]
    fn test_tee_requirement() {
        let mut runtime = HardwareRuntime::new();
        runtime.select_target(HardwareTarget::GenericCPU).unwrap();

        let result = runtime.simulate_execution(1.0, true);

        assert!(matches!(result, Err(RuntimeError::TEERequired)));
    }
}
