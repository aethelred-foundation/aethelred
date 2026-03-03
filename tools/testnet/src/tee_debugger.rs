//! TEE Remote Attestation Debugger
//!
//! The Tremendous Value: Demystifies the "Black Box" of Trusted Execution Environments
//!
//! "See? The data entered the enclave here, was decrypted here, and the result left here."
//!
//! This tool lets developers who have NEVER worked with confidential computing
//! understand exactly what happens inside a TEE - making Aethelred's security
//! model tangible and learnable.
//!
//! ## Why This Is Tremendous Value (Not Table Stakes)
//!
//! Table Stakes: "We use TEEs for security"
//! Tremendous Value: "Watch your data flow through the enclave in real-time,
//!                   see the attestation being generated, understand WHY
//!                   a bank can trust this computation"
//!
//! ## Key Features
//!
//! 1. **Visual Enclave Journey** - Step-by-step visualization of data flow
//! 2. **Attestation Inspector** - Decode and explain every field of an attestation
//! 3. **Memory Boundary Visualizer** - See the encrypted/unencrypted boundaries
//! 4. **Side-Channel Attack Simulator** - Demonstrate why TEEs are secure
//! 5. **Multi-TEE Comparison** - Intel SGX vs AMD SEV vs AWS Nitro differences

use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

// ============================================================================
// TEE Platform Definitions
// ============================================================================

/// Supported TEE platforms with their unique characteristics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TEEPlatform {
    /// Intel Software Guard Extensions
    IntelSGX {
        /// SGX version (1, 2, or 2+)
        version: u8,
        /// Enclave Page Cache size in MB
        epc_size_mb: u32,
        /// Flexible Launch Control enabled
        flc_enabled: bool,
    },
    /// AMD Secure Encrypted Virtualization
    AMDSEV {
        /// SEV variant: SEV, SEV-ES, SEV-SNP
        variant: SEVVariant,
        /// ASID (Address Space ID) count
        asid_count: u32,
    },
    /// AWS Nitro Enclaves
    AWSNitro {
        /// Enclave vCPU count
        vcpu_count: u8,
        /// Memory in MB
        memory_mb: u32,
        /// NSM (Nitro Security Module) version
        nsm_version: String,
    },
    /// ARM TrustZone (for mobile/embedded)
    ARMTrustZone {
        /// Secure world memory size in MB
        secure_memory_mb: u32,
    },
    /// Mock TEE for development
    MockTEE {
        /// Simulated attestation delay
        simulated_latency_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SEVVariant {
    /// Basic SEV - memory encryption only
    SEV,
    /// SEV-ES - adds encrypted register state
    SEVES,
    /// SEV-SNP - adds memory integrity
    SEVSNP,
}

impl std::fmt::Display for TEEPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TEEPlatform::IntelSGX { version, .. } => write!(f, "Intel SGX v{}", version),
            TEEPlatform::AMDSEV { variant, .. } => write!(f, "AMD {:?}", variant),
            TEEPlatform::AWSNitro { .. } => write!(f, "AWS Nitro Enclave"),
            TEEPlatform::ARMTrustZone { .. } => write!(f, "ARM TrustZone"),
            TEEPlatform::MockTEE { .. } => write!(f, "Mock TEE (Development)"),
        }
    }
}

// ============================================================================
// Enclave Journey Visualization
// ============================================================================

/// Represents a single step in the enclave data journey
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveJourneyStep {
    /// Step number in the journey
    pub step_number: u32,
    /// Human-readable title
    pub title: String,
    /// What happens at this step
    pub description: String,
    /// Technical details (for advanced users)
    pub technical_details: String,
    /// Visual representation (ASCII art)
    pub visualization: String,
    /// Data state at this step
    pub data_state: DataState,
    /// Security properties active at this step
    pub security_properties: Vec<SecurityProperty>,
    /// Duration of this step
    pub duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataState {
    /// Data is encrypted, outside enclave
    EncryptedExternal {
        encryption_scheme: String,
        key_derivation: String,
    },
    /// Data is being transferred into enclave
    InTransit {
        from: String,
        to: String,
        protection: String,
    },
    /// Data is decrypted inside enclave
    DecryptedInternal {
        memory_region: String,
        access_control: String,
    },
    /// Data is being processed
    Processing {
        operation: String,
        isolation_level: String,
    },
    /// Result is sealed (encrypted for storage)
    Sealed {
        sealing_policy: String,
        bound_to: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProperty {
    /// Property name
    pub name: String,
    /// Is this property active?
    pub active: bool,
    /// Why this matters
    pub significance: String,
    /// What attacks this prevents
    pub prevents: Vec<String>,
}

/// The complete journey of data through a TEE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveJourney {
    /// Unique journey ID
    pub journey_id: String,
    /// TEE platform being visualized
    pub platform: TEEPlatform,
    /// All steps in the journey
    pub steps: Vec<EnclaveJourneyStep>,
    /// Summary for non-technical stakeholders
    pub executive_summary: String,
    /// Total journey time
    pub total_duration: Duration,
}

impl EnclaveJourney {
    /// Create a standard AI inference journey
    pub fn ai_inference_journey(platform: TEEPlatform, model_name: &str) -> Self {
        let steps = vec![
            EnclaveJourneyStep {
                step_number: 1,
                title: "📥 Data Arrives (Encrypted)".to_string(),
                description: format!(
                    "The patient's medical data arrives at the {} enclave, \
                    still encrypted with the hospital's key. At this point, \
                    NO ONE can read it - not even the cloud provider.",
                    platform
                ),
                technical_details: "TLS 1.3 terminated at enclave boundary. \
                    Data wrapped in enclave-specific encryption envelope.".to_string(),
                visualization: r#"
    ┌─────────────────────────────────────────────────────────────┐
    │                    UNTRUSTED WORLD                          │
    │  ┌──────────────┐                                          │
    │  │ Hospital DB  │─────🔐──────┐                            │
    │  └──────────────┘             │                            │
    │                               ▼                            │
    │  ══════════════════════════════════════════════════════    │
    │  ║             ENCLAVE BOUNDARY                       ║    │
    │  ║  ┌────────────────────────────────────────────┐   ║    │
    │  ║  │ 🔐 Encrypted Data Received                 │   ║    │
    │  ║  │ • Cannot be read by cloud provider         │   ║    │
    │  ║  │ • Cannot be read by OS/hypervisor          │   ║    │
    │  ║  │ • Only enclave has decryption key          │   ║    │
    │  ║  └────────────────────────────────────────────┘   ║    │
    │  ══════════════════════════════════════════════════════    │
    └─────────────────────────────────────────────────────────────┘
                "#.to_string(),
                data_state: DataState::EncryptedExternal {
                    encryption_scheme: "AES-256-GCM".to_string(),
                    key_derivation: "ECDH with enclave report key".to_string(),
                },
                security_properties: vec![
                    SecurityProperty {
                        name: "Confidentiality".to_string(),
                        active: true,
                        significance: "Data cannot be read by anyone".to_string(),
                        prevents: vec![
                            "Cloud provider snooping".to_string(),
                            "Man-in-the-middle attacks".to_string(),
                        ],
                    },
                ],
                duration: Duration::from_micros(150),
            },
            EnclaveJourneyStep {
                step_number: 2,
                title: "🔓 Decryption Inside Enclave".to_string(),
                description: "The enclave uses its private key (which never leaves \
                    the hardware) to decrypt the data. This decryption happens in \
                    protected memory that even the operating system cannot access.".to_string(),
                technical_details: "SGX sealing key derived from MRENCLAVE measurement. \
                    Decryption occurs in EPC (Enclave Page Cache) with hardware-enforced \
                    access controls.".to_string(),
                visualization: r#"
    ┌─────────────────────────────────────────────────────────────┐
    │  ══════════════════════════════════════════════════════    │
    │  ║             ENCLAVE BOUNDARY                       ║    │
    │  ║                                                    ║    │
    │  ║  ┌────────────────┐      ┌────────────────────┐   ║    │
    │  ║  │ 🔐 Encrypted   │─────▶│ 🔓 DECRYPTING...   │   ║    │
    │  ║  │    Data        │      │                    │   ║    │
    │  ║  └────────────────┘      │  Using hardware    │   ║    │
    │  ║                          │  private key that  │   ║    │
    │  ║  ┌────────────────────┐  │  NEVER leaves CPU  │   ║    │
    │  ║  │ 🔑 Enclave Key     │──┘                    │   ║    │
    │  ║  │ (Hardware-bound)   │  └────────────────────┘   ║    │
    │  ║  └────────────────────┘                           ║    │
    │  ║                                                    ║    │
    │  ║  ⚠️  OS/Hypervisor CANNOT access this memory      ║    │
    │  ══════════════════════════════════════════════════════    │
    └─────────────────────────────────────────────────────────────┘
                "#.to_string(),
                data_state: DataState::InTransit {
                    from: "Encrypted buffer".to_string(),
                    to: "Protected enclave memory".to_string(),
                    protection: "Hardware memory encryption (MEE)".to_string(),
                },
                security_properties: vec![
                    SecurityProperty {
                        name: "Memory Isolation".to_string(),
                        active: true,
                        significance: "Only enclave code can access this memory".to_string(),
                        prevents: vec![
                            "OS-level attacks".to_string(),
                            "Hypervisor snooping".to_string(),
                            "DMA attacks".to_string(),
                        ],
                    },
                ],
                duration: Duration::from_micros(250),
            },
            EnclaveJourneyStep {
                step_number: 3,
                title: "📊 Data is Now Plaintext (But Safe!)".to_string(),
                description: format!(
                    "The patient data is now in plaintext INSIDE the enclave. \
                    This is the ONLY place it exists unencrypted. The {} \
                    model can now process it.",
                    model_name
                ),
                technical_details: "Data resides in EPC pages. Access controlled by \
                    EPCM (Enclave Page Cache Map). Any access from outside enclave \
                    triggers #GP fault.".to_string(),
                visualization: r#"
    ┌─────────────────────────────────────────────────────────────┐
    │  ══════════════════════════════════════════════════════    │
    │  ║             ENCLAVE BOUNDARY                       ║    │
    │  ║                                                    ║    │
    │  ║  ┌────────────────────────────────────────────┐   ║    │
    │  ║  │           PLAINTEXT DATA                   │   ║    │
    │  ║  │  ┌──────────────────────────────────────┐ │   ║    │
    │  ║  │  │ Patient: John Doe                    │ │   ║    │
    │  ║  │  │ Age: 45                              │ │   ║    │
    │  ║  │  │ Lab Results: [A1C: 6.2, ...]         │ │   ║    │
    │  ║  │  │ Medical History: [...]               │ │   ║    │
    │  ║  │  └──────────────────────────────────────┘ │   ║    │
    │  ║  │                                           │   ║    │
    │  ║  │  ✅ Readable by: Enclave code ONLY        │   ║    │
    │  ║  │  ❌ NOT readable by: Cloud, OS, Admin     │   ║    │
    │  ║  └────────────────────────────────────────────┘   ║    │
    │  ══════════════════════════════════════════════════════    │
    │                                                             │
    │  ❌ BLOCKED: Cloud provider trying to read memory           │
    │  ❌ BLOCKED: Operating system trying to read memory         │
    │  ❌ BLOCKED: Hardware debugger trying to read memory        │
    └─────────────────────────────────────────────────────────────┘
                "#.to_string(),
                data_state: DataState::DecryptedInternal {
                    memory_region: "EPC Page 0x7F000000".to_string(),
                    access_control: "EPCM + Hardware Encryption".to_string(),
                },
                security_properties: vec![
                    SecurityProperty {
                        name: "Confidentiality".to_string(),
                        active: true,
                        significance: "Data is plaintext but completely isolated".to_string(),
                        prevents: vec!["All external access".to_string()],
                    },
                    SecurityProperty {
                        name: "Integrity".to_string(),
                        active: true,
                        significance: "Any tampering is detected by hardware".to_string(),
                        prevents: vec!["Memory corruption attacks".to_string()],
                    },
                ],
                duration: Duration::from_micros(50),
            },
            EnclaveJourneyStep {
                step_number: 4,
                title: "🧠 AI Model Processes Data".to_string(),
                description: format!(
                    "The {} model runs inference on the patient data. \
                    The model weights are ALSO inside the enclave - \
                    protecting both the data AND the proprietary AI model.",
                    model_name
                ),
                technical_details: "ONNX runtime executes within enclave. Model weights \
                    loaded from sealed storage. All intermediate tensors remain in EPC.".to_string(),
                visualization: r#"
    ┌─────────────────────────────────────────────────────────────┐
    │  ══════════════════════════════════════════════════════    │
    │  ║             ENCLAVE BOUNDARY                       ║    │
    │  ║                                                    ║    │
    │  ║  ┌──────────────┐      ┌──────────────────────┐   ║    │
    │  ║  │ Patient Data │─────▶│    🧠 AI MODEL       │   ║    │
    │  ║  └──────────────┘      │                      │   ║    │
    │  ║                        │  ┌────────────────┐  │   ║    │
    │  ║  ┌──────────────┐      │  │ Input Layer    │  │   ║    │
    │  ║  │ Model Weights│─────▶│  │     ▼          │  │   ║    │
    │  ║  │ (Protected)  │      │  │ Hidden Layers  │  │   ║    │
    │  ║  └──────────────┘      │  │     ▼          │  │   ║    │
    │  ║                        │  │ Output Layer   │  │   ║    │
    │  ║                        │  └───────┬────────┘  │   ║    │
    │  ║                        │          │           │   ║    │
    │  ║                        └──────────┼───────────┘   ║    │
    │  ║                                   ▼               ║    │
    │  ║                        ┌──────────────────────┐   ║    │
    │  ║                        │ RESULT: Low Risk     │   ║    │
    │  ║                        │ Confidence: 94.2%    │   ║    │
    │  ║                        └──────────────────────┘   ║    │
    │  ══════════════════════════════════════════════════════    │
    └─────────────────────────────────────────────────────────────┘
                "#.to_string(),
                data_state: DataState::Processing {
                    operation: format!("{} inference", model_name),
                    isolation_level: "Full enclave isolation".to_string(),
                },
                security_properties: vec![
                    SecurityProperty {
                        name: "Model Protection".to_string(),
                        active: true,
                        significance: "Proprietary AI model is also protected".to_string(),
                        prevents: vec!["Model theft".to_string(), "Model extraction attacks".to_string()],
                    },
                    SecurityProperty {
                        name: "Computation Integrity".to_string(),
                        active: true,
                        significance: "No one can alter the computation".to_string(),
                        prevents: vec!["Result manipulation".to_string()],
                    },
                ],
                duration: Duration::from_millis(45),
            },
            EnclaveJourneyStep {
                step_number: 5,
                title: "📜 Attestation Generated".to_string(),
                description: "The enclave generates a cryptographic ATTESTATION - \
                    a proof signed by the CPU hardware that says: \
                    'This exact code ran on this exact data in a genuine TEE.'".to_string(),
                technical_details: "EREPORT generated with MRENCLAVE/MRSIGNER measurements. \
                    Quote signed by Intel's attestation key (EPID/DCAP). Includes SHA-256 \
                    of inputs and outputs.".to_string(),
                visualization: r#"
    ┌─────────────────────────────────────────────────────────────┐
    │  ══════════════════════════════════════════════════════    │
    │  ║             ENCLAVE BOUNDARY                       ║    │
    │  ║                                                    ║    │
    │  ║  ┌────────────────────────────────────────────┐   ║    │
    │  ║  │         📜 ATTESTATION REPORT              │   ║    │
    │  ║  │                                            │   ║    │
    │  ║  │  MRENCLAVE: 0x7a3b9c...                   │   ║    │
    │  ║  │  (Hash of enclave code - proves WHAT ran) │   ║    │
    │  ║  │                                            │   ║    │
    │  ║  │  Input Hash:  0x4f2e1d...                 │   ║    │
    │  ║  │  Output Hash: 0x8c7b2a...                 │   ║    │
    │  ║  │  (Proves WHAT was processed)              │   ║    │
    │  ║  │                                            │   ║    │
    │  ║  │  CPU SVN: 12                              │   ║    │
    │  ║  │  (Security version - proves WHERE)         │   ║    │
    │  ║  │                                            │   ║    │
    │  ║  │  ┌──────────────────────────────────────┐ │   ║    │
    │  ║  │  │  🔏 SIGNED BY INTEL HARDWARE KEY     │ │   ║    │
    │  ║  │  │  (Unforgeable - proves it's GENUINE) │ │   ║    │
    │  ║  │  └──────────────────────────────────────┘ │   ║    │
    │  ║  └────────────────────────────────────────────┘   ║    │
    │  ══════════════════════════════════════════════════════    │
    └─────────────────────────────────────────────────────────────┘
                "#.to_string(),
                data_state: DataState::Processing {
                    operation: "Attestation generation".to_string(),
                    isolation_level: "Hardware-backed".to_string(),
                },
                security_properties: vec![
                    SecurityProperty {
                        name: "Non-Repudiation".to_string(),
                        active: true,
                        significance: "Cannot deny the computation happened".to_string(),
                        prevents: vec!["Denial of execution".to_string()],
                    },
                    SecurityProperty {
                        name: "Authenticity".to_string(),
                        active: true,
                        significance: "Proves genuine TEE hardware".to_string(),
                        prevents: vec!["Fake TEE attacks".to_string()],
                    },
                ],
                duration: Duration::from_millis(5),
            },
            EnclaveJourneyStep {
                step_number: 6,
                title: "📤 Result Exits (Encrypted + Attested)".to_string(),
                description: "The result leaves the enclave, encrypted for the recipient. \
                    The attestation travels WITH the result, proving it came from a genuine \
                    TEE computation.".to_string(),
                technical_details: "Output sealed with recipient's public key. Attestation \
                    quote attached. Can be verified by any party using Intel's attestation \
                    service or DCAP.".to_string(),
                visualization: r#"
    ┌─────────────────────────────────────────────────────────────┐
    │  ══════════════════════════════════════════════════════    │
    │  ║             ENCLAVE BOUNDARY                       ║    │
    │  ║                                                    ║    │
    │  ║  ┌──────────────┐    ┌──────────────────────┐     ║    │
    │  ║  │ 🔐 Encrypted │    │ 📜 Attestation       │     ║    │
    │  ║  │    Result    │    │    Quote             │     ║    │
    │  ║  └──────┬───────┘    └──────────┬───────────┘     ║    │
    │  ║         │                       │                  ║    │
    │  ══════════╪═══════════════════════╪═══════════════════    │
    │            │                       │                        │
    │            ▼                       ▼                        │
    │  ┌─────────────────────────────────────────────────────┐   │
    │  │              UNTRUSTED WORLD                        │   │
    │  │                                                     │   │
    │  │  ┌─────────────────────────────────────────────┐   │   │
    │  │  │  📦 VERIFIED RESULT PACKAGE                  │   │   │
    │  │  │                                             │   │   │
    │  │  │  Result: "Low Risk" (encrypted)             │   │   │
    │  │  │  Proof:  Intel-signed attestation           │   │   │
    │  │  │                                             │   │   │
    │  │  │  ✅ Anyone can verify this came from a TEE  │   │   │
    │  │  │  ✅ No one can forge this result            │   │   │
    │  │  │  ✅ Bank can trust this computation         │   │   │
    │  │  └─────────────────────────────────────────────┘   │   │
    │  └─────────────────────────────────────────────────────┘   │
    └─────────────────────────────────────────────────────────────┘
                "#.to_string(),
                data_state: DataState::Sealed {
                    sealing_policy: "Recipient public key".to_string(),
                    bound_to: "Attestation quote".to_string(),
                },
                security_properties: vec![
                    SecurityProperty {
                        name: "Verifiability".to_string(),
                        active: true,
                        significance: "Any party can verify the computation".to_string(),
                        prevents: vec!["Disputes about computation".to_string()],
                    },
                    SecurityProperty {
                        name: "End-to-End Encryption".to_string(),
                        active: true,
                        significance: "Result only readable by intended recipient".to_string(),
                        prevents: vec!["Result interception".to_string()],
                    },
                ],
                duration: Duration::from_micros(200),
            },
        ];

        let total_duration: Duration = steps.iter().map(|s| s.duration).sum();

        EnclaveJourney {
            journey_id: uuid::Uuid::new_v4().to_string(),
            platform,
            steps,
            executive_summary: format!(
                "Patient data entered the secure enclave encrypted, was processed by the {} model \
                in complete isolation, and the result was returned with a cryptographic proof that \
                this computation genuinely happened in trusted hardware. At no point could any \
                external party - not the cloud provider, not the operating system, not even a \
                malicious administrator - access the plaintext data.",
                model_name
            ),
            total_duration,
        }
    }
}

// ============================================================================
// Attestation Inspector
// ============================================================================

/// Decoded attestation with human-readable explanations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationInspection {
    /// The platform this attestation is from
    pub platform: TEEPlatform,
    /// Raw attestation bytes (hex encoded)
    pub raw_hex: String,
    /// Decoded fields with explanations
    pub fields: Vec<AttestationField>,
    /// Trust chain explanation
    pub trust_chain: TrustChainExplanation,
    /// Verification status
    pub verification: VerificationStatus,
    /// What this attestation proves
    pub proves: Vec<String>,
    /// What this attestation does NOT prove
    pub does_not_prove: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationField {
    /// Field name
    pub name: String,
    /// Field value (hex)
    pub value_hex: String,
    /// Human-readable value
    pub value_human: String,
    /// What this field means
    pub explanation: String,
    /// Why this field matters for trust
    pub trust_implication: String,
    /// Byte offset in attestation
    pub byte_offset: usize,
    /// Field length in bytes
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustChainExplanation {
    /// Visual representation of trust chain
    pub visualization: String,
    /// Each link in the chain
    pub links: Vec<TrustChainLink>,
    /// Root of trust
    pub root_of_trust: String,
    /// Why this chain can be trusted
    pub why_trusted: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustChainLink {
    /// Link name
    pub name: String,
    /// What signs this link
    pub signed_by: String,
    /// What this link vouches for
    pub vouches_for: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Attestation is valid and verified
    Valid {
        verified_at: SystemTime,
        verification_service: String,
    },
    /// Attestation verification failed
    Invalid {
        reason: String,
        suggestion: String,
    },
    /// Attestation is from a mock/development environment
    MockDevelopment {
        warning: String,
    },
    /// Cannot verify (offline or service unavailable)
    Unverifiable {
        reason: String,
    },
}

/// Inspector for decoding and explaining attestations
pub struct AttestationInspector {
    /// Platform-specific decoders
    decoders: HashMap<String, Box<dyn AttestationDecoder>>,
}

pub trait AttestationDecoder: Send + Sync {
    fn decode(&self, raw: &[u8]) -> Result<Vec<AttestationField>, String>;
    fn platform_name(&self) -> &str;
}

impl AttestationInspector {
    pub fn new() -> Self {
        Self {
            decoders: HashMap::new(),
        }
    }

    /// Inspect an SGX attestation quote
    pub fn inspect_sgx_quote(&self, quote: &[u8]) -> AttestationInspection {
        let fields = vec![
            AttestationField {
                name: "Version".to_string(),
                value_hex: "0x0003".to_string(),
                value_human: "DCAP Quote Version 3".to_string(),
                explanation: "The version of the quote format. Version 3 is the latest \
                    DCAP (Data Center Attestation Primitives) format.".to_string(),
                trust_implication: "Newer versions have better security properties.".to_string(),
                byte_offset: 0,
                length: 2,
            },
            AttestationField {
                name: "Attestation Key Type".to_string(),
                value_hex: "0x0002".to_string(),
                value_human: "ECDSA-256-with-P-256".to_string(),
                explanation: "The cryptographic algorithm used to sign the quote. \
                    ECDSA with P-256 curve is a NIST-approved algorithm.".to_string(),
                trust_implication: "Strong cryptographic signature ensures authenticity.".to_string(),
                byte_offset: 2,
                length: 2,
            },
            AttestationField {
                name: "TEE Type".to_string(),
                value_hex: "0x00000000".to_string(),
                value_human: "SGX".to_string(),
                explanation: "Identifies this as an Intel SGX attestation (vs TDX).".to_string(),
                trust_implication: "Confirms the hardware type being attested.".to_string(),
                byte_offset: 4,
                length: 4,
            },
            AttestationField {
                name: "MRENCLAVE".to_string(),
                value_hex: "7a3b9c2f1e8d4a5b6c7d8e9f0a1b2c3d...".to_string(),
                value_human: "Enclave Code Measurement".to_string(),
                explanation: "A SHA-256 hash of the enclave's code and initial data. \
                    This UNIQUELY identifies EXACTLY what code is running.".to_string(),
                trust_implication: "⭐ CRITICAL: Proves WHICH code ran. If this doesn't match \
                    the expected value, the enclave is running different code!".to_string(),
                byte_offset: 112,
                length: 32,
            },
            AttestationField {
                name: "MRSIGNER".to_string(),
                value_hex: "4f2e1d0c9b8a7f6e5d4c3b2a1908...".to_string(),
                value_human: "Enclave Signer Identity".to_string(),
                explanation: "A hash of the public key that signed the enclave. \
                    This identifies WHO built and signed this enclave.".to_string(),
                trust_implication: "⭐ IMPORTANT: Proves the enclave was built by a trusted party \
                    (e.g., Aethelred). Attackers cannot forge this.".to_string(),
                byte_offset: 176,
                length: 32,
            },
            AttestationField {
                name: "ISV Product ID".to_string(),
                value_hex: "0x0001".to_string(),
                value_human: "Product: Aethelred AI Verifier".to_string(),
                explanation: "An identifier assigned by the enclave developer to \
                    distinguish different enclave products.".to_string(),
                trust_implication: "Helps identify the specific application.".to_string(),
                byte_offset: 304,
                length: 2,
            },
            AttestationField {
                name: "ISV SVN".to_string(),
                value_hex: "0x0003".to_string(),
                value_human: "Security Version 3".to_string(),
                explanation: "The security version number. Higher is newer. \
                    Used to revoke older, potentially vulnerable versions.".to_string(),
                trust_implication: "Ensures the enclave isn't an old, vulnerable version.".to_string(),
                byte_offset: 306,
                length: 2,
            },
            AttestationField {
                name: "Report Data".to_string(),
                value_hex: "8c7b2a9d0e1f2a3b4c5d6e7f8a9b0c1d...".to_string(),
                value_human: "Custom Data Hash (Input/Output Commitment)".to_string(),
                explanation: "64 bytes of custom data included in the attestation. \
                    Aethelred uses this to commit to the input and output hashes.".to_string(),
                trust_implication: "⭐ CRITICAL: This binds the attestation to specific \
                    inputs and outputs. Proves WHAT was computed.".to_string(),
                byte_offset: 368,
                length: 64,
            },
        ];

        AttestationInspection {
            platform: TEEPlatform::IntelSGX {
                version: 2,
                epc_size_mb: 256,
                flc_enabled: true,
            },
            raw_hex: hex::encode(quote),
            fields,
            trust_chain: TrustChainExplanation {
                visualization: r#"
    ┌─────────────────────────────────────────────────────────────┐
    │                    TRUST CHAIN                              │
    │                                                             │
    │  ┌───────────────────────────────────────────────────────┐ │
    │  │             INTEL ROOT OF TRUST                       │ │
    │  │  Intel's Root Signing Key (fused into every CPU)      │ │
    │  │  🔐 Impossible to forge - hardware embedded           │ │
    │  └─────────────────────────┬─────────────────────────────┘ │
    │                            │ signs                         │
    │                            ▼                               │
    │  ┌───────────────────────────────────────────────────────┐ │
    │  │           PROVISIONING CERTIFICATION KEY              │ │
    │  │  Intel's Attestation Infrastructure Key               │ │
    │  │  🔐 Intel-controlled, regularly rotated               │ │
    │  └─────────────────────────┬─────────────────────────────┘ │
    │                            │ signs                         │
    │                            ▼                               │
    │  ┌───────────────────────────────────────────────────────┐ │
    │  │           ATTESTATION KEY (This CPU)                  │ │
    │  │  Unique key for this specific processor               │ │
    │  │  🔐 Never leaves the CPU silicon                      │ │
    │  └─────────────────────────┬─────────────────────────────┘ │
    │                            │ signs                         │
    │                            ▼                               │
    │  ┌───────────────────────────────────────────────────────┐ │
    │  │           THIS ATTESTATION QUOTE                      │ │
    │  │  The quote you're inspecting right now                │ │
    │  │  ✅ Verified all the way to Intel's root              │ │
    │  └───────────────────────────────────────────────────────┘ │
    │                                                             │
    │  ═══════════════════════════════════════════════════════   │
    │  If ANY link is broken, the quote is INVALID               │
    └─────────────────────────────────────────────────────────────┘
                "#.to_string(),
                links: vec![
                    TrustChainLink {
                        name: "Intel Root Key".to_string(),
                        signed_by: "Hardware (fused in silicon)".to_string(),
                        vouches_for: "All Intel SGX processors".to_string(),
                    },
                    TrustChainLink {
                        name: "Provisioning Key".to_string(),
                        signed_by: "Intel Root Key".to_string(),
                        vouches_for: "This data center's attestation infrastructure".to_string(),
                    },
                    TrustChainLink {
                        name: "Attestation Key".to_string(),
                        signed_by: "Provisioning Key".to_string(),
                        vouches_for: "This specific CPU".to_string(),
                    },
                    TrustChainLink {
                        name: "Quote Signature".to_string(),
                        signed_by: "Attestation Key".to_string(),
                        vouches_for: "This specific enclave execution".to_string(),
                    },
                ],
                root_of_trust: "Intel's Root Signing Key, fused into the CPU during manufacturing. \
                    This key CANNOT be extracted or modified.".to_string(),
                why_trusted: "The trust chain traces back to Intel's hardware root of trust. \
                    To forge an attestation, an attacker would need to either: \
                    (1) Compromise Intel's root signing key (essentially impossible), or \
                    (2) Physically extract keys from CPU silicon (requires multi-million dollar equipment). \
                    This is why banks can trust these attestations.".to_string(),
            },
            verification: VerificationStatus::MockDevelopment {
                warning: "This is a development environment attestation. \
                    In production, attestations are verified against Intel's attestation service.".to_string(),
            },
            proves: vec![
                "✅ The exact code that ran (MRENCLAVE hash)".to_string(),
                "✅ Who built the enclave (MRSIGNER hash)".to_string(),
                "✅ The computation happened in genuine Intel SGX hardware".to_string(),
                "✅ The specific inputs and outputs (Report Data commitment)".to_string(),
                "✅ The enclave is a recent, non-revoked version (SVN)".to_string(),
                "✅ No one tampered with the computation".to_string(),
            ],
            does_not_prove: vec![
                "❌ The AI model is correct or unbiased (that's a separate concern)".to_string(),
                "❌ The input data was accurate (garbage in, garbage out still applies)".to_string(),
                "❌ The result is fair or ethical (TEE proves execution, not ethics)".to_string(),
                "❌ The enclave has no bugs (TEE protects from external attacks, not code bugs)".to_string(),
            ],
        }
    }
}

impl Default for AttestationInspector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Memory Boundary Visualizer
// ============================================================================

/// Visualizes the encrypted/unencrypted memory boundaries in a TEE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryBoundaryVisualization {
    /// ASCII art visualization
    pub visualization: String,
    /// Memory regions explanation
    pub regions: Vec<MemoryRegion>,
    /// Security boundaries
    pub boundaries: Vec<SecurityBoundary>,
    /// What happens when boundaries are crossed
    pub crossing_behaviors: Vec<BoundaryCrossingBehavior>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Region name
    pub name: String,
    /// Start address (hex)
    pub start_address: String,
    /// End address (hex)
    pub end_address: String,
    /// Is this region encrypted?
    pub encrypted: bool,
    /// Who can access this region
    pub access: Vec<String>,
    /// Protection mechanism
    pub protection: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityBoundary {
    /// Boundary name
    pub name: String,
    /// What this boundary separates
    pub separates: (String, String),
    /// Hardware enforcement
    pub hardware_enforced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundaryCrossingBehavior {
    /// Direction of crossing
    pub direction: String,
    /// What happens
    pub behavior: String,
    /// Security implication
    pub security_impact: String,
}

impl MemoryBoundaryVisualization {
    pub fn sgx_visualization() -> Self {
        MemoryBoundaryVisualization {
            visualization: r#"
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                    INTEL SGX MEMORY LAYOUT                                 ║
    ╠═══════════════════════════════════════════════════════════════════════════╣
    ║                                                                            ║
    ║  PHYSICAL RAM                                                             ║
    ║  ┌────────────────────────────────────────────────────────────────────┐   ║
    ║  │                                                                    │   ║
    ║  │   NORMAL MEMORY (Unencrypted - Visible to OS/Hypervisor)          │   ║
    ║  │   ┌──────────────────────────────────────────────────────────┐    │   ║
    ║  │   │  Kernel Space                    │ User Space            │    │   ║
    ║  │   │  • OS can read/write            │ • OS can read/write   │    │   ║
    ║  │   │  • Hypervisor can read/write    │ • Apps can read       │    │   ║
    ║  │   └──────────────────────────────────────────────────────────┘    │   ║
    ║  │                                                                    │   ║
    ║  │   ═══════════════════════════════════════════════════════════════ │   ║
    ║  │   ║           ⚡ ENCLAVE PAGE CACHE (EPC) - ENCRYPTED ⚡          ║ │   ║
    ║  │   ═══════════════════════════════════════════════════════════════ │   ║
    ║  │   ║                                                              ║ │   ║
    ║  │   ║  🔒 ENCRYPTED WITH MEMORY ENCRYPTION ENGINE (MEE)           ║ │   ║
    ║  │   ║  ┌────────────────────────────────────────────────────────┐ ║ │   ║
    ║  │   ║  │                                                        │ ║ │   ║
    ║  │   ║  │   ENCLAVE MEMORY                                       │ ║ │   ║
    ║  │   ║  │   • OS CANNOT read        ❌                           │ ║ │   ║
    ║  │   ║  │   • Hypervisor CANNOT read ❌                          │ ║ │   ║
    ║  │   ║  │   • DMA CANNOT access      ❌                          │ ║ │   ║
    ║  │   ║  │   • Only enclave code ✅                               │ ║ │   ║
    ║  │   ║  │                                                        │ ║ │   ║
    ║  │   ║  │   ┌──────────────────────────────────────────────┐    │ ║ │   ║
    ║  │   ║  │   │  Your Plaintext Data Lives Here Safely       │    │ ║ │   ║
    ║  │   ║  │   │  • Patient records (decrypted)               │    │ ║ │   ║
    ║  │   ║  │   │  • AI model weights                          │    │ ║ │   ║
    ║  │   ║  │   │  • Intermediate computations                 │    │ ║ │   ║
    ║  │   ║  │   └──────────────────────────────────────────────┘    │ ║ │   ║
    ║  │   ║  │                                                        │ ║ │   ║
    ║  │   ║  └────────────────────────────────────────────────────────┘ ║ │   ║
    ║  │   ║                                                              ║ │   ║
    ║  │   ═══════════════════════════════════════════════════════════════ │   ║
    ║  │                                                                    │   ║
    ║  └────────────────────────────────────────────────────────────────────┘   ║
    ║                                                                            ║
    ║  LEGEND:                                                                   ║
    ║  ═══════ = Hardware-enforced encryption boundary                          ║
    ║  🔒 = AES-128 encryption with integrity (MEE)                             ║
    ║  ❌ = Access blocked by CPU hardware                                       ║
    ║  ✅ = Access permitted                                                     ║
    ║                                                                            ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
            "#.to_string(),
            regions: vec![
                MemoryRegion {
                    name: "Normal Memory".to_string(),
                    start_address: "0x0000_0000".to_string(),
                    end_address: "0x7FFF_FFFF".to_string(),
                    encrypted: false,
                    access: vec!["OS".to_string(), "Hypervisor".to_string(), "Applications".to_string()],
                    protection: "Standard page permissions only".to_string(),
                },
                MemoryRegion {
                    name: "Enclave Page Cache (EPC)".to_string(),
                    start_address: "0x8000_0000".to_string(),
                    end_address: "0x87FF_FFFF".to_string(),
                    encrypted: true,
                    access: vec!["Enclave code only".to_string()],
                    protection: "Memory Encryption Engine (MEE) - AES-128-CTR + integrity".to_string(),
                },
            ],
            boundaries: vec![
                SecurityBoundary {
                    name: "EPC Boundary".to_string(),
                    separates: ("Normal Memory".to_string(), "Enclave Memory".to_string()),
                    hardware_enforced: true,
                },
            ],
            crossing_behaviors: vec![
                BoundaryCrossingBehavior {
                    direction: "Enclave → Normal (EEXIT)".to_string(),
                    behavior: "Data is automatically encrypted before leaving".to_string(),
                    security_impact: "No plaintext ever visible outside enclave".to_string(),
                },
                BoundaryCrossingBehavior {
                    direction: "Normal → Enclave (EENTER)".to_string(),
                    behavior: "Data must be explicitly decrypted inside".to_string(),
                    security_impact: "Enclave controls when/if decryption happens".to_string(),
                },
                BoundaryCrossingBehavior {
                    direction: "OS trying to read EPC".to_string(),
                    behavior: "CPU generates #GP (General Protection) fault".to_string(),
                    security_impact: "OS access is PHYSICALLY blocked by hardware".to_string(),
                },
            ],
        }
    }
}

// ============================================================================
// Side-Channel Attack Simulator
// ============================================================================

/// Simulates and explains side-channel attacks (and why TEEs resist them)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideChannelSimulation {
    /// Attack name
    pub attack_name: String,
    /// Attack category
    pub category: AttackCategory,
    /// How the attack works
    pub explanation: String,
    /// Visual demonstration
    pub demonstration: String,
    /// TEE's defense
    pub tee_defense: String,
    /// Is the attack mitigated?
    pub mitigated: bool,
    /// Additional mitigations required
    pub additional_mitigations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackCategory {
    /// Timing-based attacks
    Timing,
    /// Cache-based attacks
    Cache,
    /// Power analysis attacks
    Power,
    /// Electromagnetic attacks
    Electromagnetic,
    /// Speculative execution attacks
    Speculative,
    /// Memory access pattern attacks
    MemoryPattern,
}

/// Simulator for demonstrating side-channel attacks
pub struct SideChannelSimulator;

impl SideChannelSimulator {
    pub fn simulate_cache_timing_attack() -> SideChannelSimulation {
        SideChannelSimulation {
            attack_name: "Prime+Probe Cache Attack".to_string(),
            category: AttackCategory::Cache,
            explanation: "An attacker fills the CPU cache with their own data, then \
                measures how long their data takes to access after the enclave runs. \
                Cache misses (slower access) reveal which cache lines the enclave used, \
                potentially leaking secret-dependent memory access patterns.".to_string(),
            demonstration: r#"
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                     PRIME+PROBE ATTACK DEMONSTRATION                         │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │                                                                              │
    │  STEP 1: PRIME - Attacker fills cache                                       │
    │  ┌─────────────────────────────────────────────────────────────────────┐    │
    │  │  L1 CACHE                                                           │    │
    │  │  ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐                │    │
    │  │  │ A1  │ A2  │ A3  │ A4  │ A5  │ A6  │ A7  │ A8  │  ← Attacker    │    │
    │  │  └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘                │    │
    │  └─────────────────────────────────────────────────────────────────────┘    │
    │                                                                              │
    │  STEP 2: VICTIM - Enclave runs, evicts some cache lines                     │
    │  ┌─────────────────────────────────────────────────────────────────────┐    │
    │  │  L1 CACHE (after enclave)                                           │    │
    │  │  ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐                │    │
    │  │  │ A1  │ V1  │ A3  │ V2  │ A5  │ A6  │ V3  │ A8  │  ← Some evicted│    │
    │  │  └─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘                │    │
    │  │        ↑           ↑                 ↑                              │    │
    │  │      MISS        MISS              MISS                             │    │
    │  └─────────────────────────────────────────────────────────────────────┘    │
    │                                                                              │
    │  STEP 3: PROBE - Attacker measures access times                             │
    │  ┌─────────────────────────────────────────────────────────────────────┐    │
    │  │  Access Times (cycles):                                             │    │
    │  │  A1: 4   A2: 80⚠️  A3: 4   A4: 75⚠️  A5: 4   A6: 4   A7: 82⚠️  A8: 4│    │
    │  │                                                                     │    │
    │  │  ⚠️ = CACHE MISS = Enclave accessed this memory region!             │    │
    │  │                                                                     │    │
    │  │  LEAKED: Enclave accessed addresses that map to cache lines 2,4,7   │    │
    │  └─────────────────────────────────────────────────────────────────────┘    │
    │                                                                              │
    │  ❌ ATTACK POTENTIALLY REVEALS: Secret-dependent memory access patterns     │
    │     Example: If enclave does table[secret_byte], attacker learns secret!    │
    │                                                                              │
    └─────────────────────────────────────────────────────────────────────────────┘
            "#.to_string(),
            tee_defense: r#"
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                     TEE DEFENSES AGAINST CACHE ATTACKS                       │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │                                                                              │
    │  1. CACHE PARTITIONING (Hardware)                                           │
    │  ┌─────────────────────────────────────────────────────────────────────┐    │
    │  │  L1 CACHE                                                           │    │
    │  │  ┌─────────────────────┬──────────────────────┐                    │    │
    │  │  │  ENCLAVE PARTITION  │  NORMAL PARTITION    │                    │    │
    │  │  │  ┌───┬───┬───┬───┐ │  ┌───┬───┬───┬───┐   │                    │    │
    │  │  │  │V1 │V2 │V3 │V4 │ │  │A1 │A2 │A3 │A4 │   │ ← Separate!       │    │
    │  │  │  └───┴───┴───┴───┘ │  └───┴───┴───┴───┘   │                    │    │
    │  │  │  🔒 Enclave Only    │  👁️ Attacker sees    │                    │    │
    │  │  └─────────────────────┴──────────────────────┘                    │    │
    │  │  ✅ Enclave never evicts attacker's cache lines!                   │    │
    │  └─────────────────────────────────────────────────────────────────────┘    │
    │                                                                              │
    │  2. OBLIVIOUS RAM (Software Defense in Aethelred)                           │
    │  ┌─────────────────────────────────────────────────────────────────────┐    │
    │  │  Instead of: table[secret]   ← Leaks which index!                   │    │
    │  │                                                                     │    │
    │  │  We do:      for i in 0..table.len():                              │    │
    │  │                result = (i == secret) ? table[i] : result           │    │
    │  │                                                                     │    │
    │  │  ✅ Access ALL indices - attacker can't distinguish which matters!  │    │
    │  └─────────────────────────────────────────────────────────────────────┘    │
    │                                                                              │
    │  3. CONSTANT-TIME OPERATIONS (Crypto Best Practice)                         │
    │  ┌─────────────────────────────────────────────────────────────────────┐    │
    │  │  All cryptographic operations take the SAME TIME regardless of     │    │
    │  │  input, eliminating timing-based information leakage.               │    │
    │  └─────────────────────────────────────────────────────────────────────┘    │
    │                                                                              │
    └─────────────────────────────────────────────────────────────────────────────┘
            "#.to_string(),
            mitigated: true,
            additional_mitigations: vec![
                "Use ORAM (Oblivious RAM) for secret-dependent memory access".to_string(),
                "Enable cache partitioning on supporting hardware".to_string(),
                "Use constant-time cryptographic implementations".to_string(),
                "Avoid secret-dependent branches".to_string(),
            ],
        }
    }

    pub fn simulate_spectre_attack() -> SideChannelSimulation {
        SideChannelSimulation {
            attack_name: "Spectre V1 (Bounds Check Bypass)".to_string(),
            category: AttackCategory::Speculative,
            explanation: "The CPU speculatively executes code before bounds checks complete. \
                An attacker can trick the CPU into speculatively reading secret memory, \
                leaving traces in the cache that can be detected even after the speculation \
                is rolled back.".to_string(),
            demonstration: r#"
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                     SPECTRE V1 ATTACK DEMONSTRATION                          │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │                                                                              │
    │  VULNERABLE CODE:                                                            │
    │  ┌─────────────────────────────────────────────────────────────────────┐    │
    │  │  if (x < array_size) {           // Bounds check                    │    │
    │  │      y = array[x];               // Array access                    │    │
    │  │      z = probe_array[y * 4096];  // Cache probe (leaks y!)         │    │
    │  │  }                                                                  │    │
    │  └─────────────────────────────────────────────────────────────────────┘    │
    │                                                                              │
    │  ATTACK SEQUENCE:                                                            │
    │  ┌─────────────────────────────────────────────────────────────────────┐    │
    │  │                                                                     │    │
    │  │  1. Train branch predictor: Call with valid x many times           │    │
    │  │     CPU learns: "this branch is usually TAKEN"                      │    │
    │  │                                                                     │    │
    │  │  2. Flush array_size from cache (make bounds check slow)           │    │
    │  │                                                                     │    │
    │  │  3. Call with malicious x (out of bounds, pointing to secret)      │    │
    │  │                                                                     │    │
    │  │  4. CPU speculates: "Branch will be taken" (based on training)     │    │
    │  │     │                                                               │    │
    │  │     ├─▶ Speculatively reads array[malicious_x] = SECRET!           │    │
    │  │     └─▶ Speculatively accesses probe_array[SECRET * 4096]          │    │
    │  │         └─▶ This access stays in CACHE even after rollback!        │    │
    │  │                                                                     │    │
    │  │  5. Bounds check completes: "x >= array_size" → Rollback!          │    │
    │  │     But the cache state change PERSISTS!                           │    │
    │  │                                                                     │    │
    │  │  6. Attacker probes cache to find which probe_array entry is hot   │    │
    │  │     Hot entry / 4096 = SECRET VALUE!                               │    │
    │  │                                                                     │    │
    │  └─────────────────────────────────────────────────────────────────────┘    │
    │                                                                              │
    │  ❌ ATTACK REVEALS: Memory contents outside of bounds!                       │
    │                                                                              │
    └─────────────────────────────────────────────────────────────────────────────┘
            "#.to_string(),
            tee_defense: r#"
    ┌─────────────────────────────────────────────────────────────────────────────┐
    │                     SGX DEFENSES AGAINST SPECTRE                             │
    ├─────────────────────────────────────────────────────────────────────────────┤
    │                                                                              │
    │  1. LFENCE BARRIERS (Software Mitigation)                                   │
    │  ┌─────────────────────────────────────────────────────────────────────┐    │
    │  │  if (x < array_size) {                                              │    │
    │  │      lfence;                    // ⚡ SPECULATION BARRIER!          │    │
    │  │      y = array[x];              // Only executed after check        │    │
    │  │  }                                                                  │    │
    │  │                                                                     │    │
    │  │  ✅ CPU cannot speculate past LFENCE instruction                   │    │
    │  └─────────────────────────────────────────────────────────────────────┘    │
    │                                                                              │
    │  2. RETPOLINE (Return Trampoline)                                           │
    │  ┌─────────────────────────────────────────────────────────────────────┐    │
    │  │  Replaces indirect jumps with a pattern that prevents speculation   │    │
    │  │  Aethelred's enclave code is compiled with -mretpoline              │    │
    │  └─────────────────────────────────────────────────────────────────────┘    │
    │                                                                              │
    │  3. MICROCODE UPDATES (Hardware)                                            │
    │  ┌─────────────────────────────────────────────────────────────────────┐    │
    │  │  Intel has released microcode updates that:                         │    │
    │  │  • Flush branch predictors on enclave entry/exit                   │    │
    │  │  • Prevent cross-domain speculation                                 │    │
    │  │  • Aethelred validators require latest microcode                   │    │
    │  └─────────────────────────────────────────────────────────────────────┘    │
    │                                                                              │
    │  4. ATTESTATION INCLUDES CPU SVN                                            │
    │  ┌─────────────────────────────────────────────────────────────────────┐    │
    │  │  Every attestation includes the Security Version Number (SVN)       │    │
    │  │  Clients can REJECT attestations from CPUs without patches          │    │
    │  │  ✅ Only patched CPUs can produce valid attestations               │    │
    │  └─────────────────────────────────────────────────────────────────────┘    │
    │                                                                              │
    └─────────────────────────────────────────────────────────────────────────────┘
            "#.to_string(),
            mitigated: true,
            additional_mitigations: vec![
                "Compile with speculation barriers (-mspeculative-load-hardening)".to_string(),
                "Use retpoline for indirect calls".to_string(),
                "Require latest microcode in attestation policy".to_string(),
                "Implement index masking for array accesses".to_string(),
            ],
        }
    }
}

// ============================================================================
// Multi-TEE Comparison
// ============================================================================

/// Compares different TEE platforms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEComparison {
    /// Platforms being compared
    pub platforms: Vec<TEEPlatform>,
    /// Comparison table
    pub comparison_table: String,
    /// Detailed differences
    pub detailed_differences: Vec<TEEDifference>,
    /// Recommendation based on use case
    pub recommendations: Vec<TEERecommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEDifference {
    /// Feature being compared
    pub feature: String,
    /// Value for each platform
    pub platform_values: HashMap<String, String>,
    /// Why this matters
    pub significance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEERecommendation {
    /// Use case
    pub use_case: String,
    /// Recommended platform
    pub recommended: TEEPlatform,
    /// Why
    pub reasoning: String,
}

impl TEEComparison {
    pub fn full_comparison() -> Self {
        TEEComparison {
            platforms: vec![
                TEEPlatform::IntelSGX { version: 2, epc_size_mb: 256, flc_enabled: true },
                TEEPlatform::AMDSEV { variant: SEVVariant::SEVSNP, asid_count: 509 },
                TEEPlatform::AWSNitro { vcpu_count: 4, memory_mb: 8192, nsm_version: "1.0".to_string() },
            ],
            comparison_table: r#"
    ╔═══════════════════════════════════════════════════════════════════════════════════════════╗
    ║                          TEE PLATFORM COMPARISON                                           ║
    ╠═══════════════════╦═══════════════════╦═══════════════════╦═══════════════════════════════╣
    ║     Feature       ║    Intel SGX      ║    AMD SEV-SNP    ║    AWS Nitro Enclaves        ║
    ╠═══════════════════╬═══════════════════╬═══════════════════╬═══════════════════════════════╣
    ║ Isolation Unit    ║ Process (Enclave) ║ VM (Guest)        ║ VM (Enclave)                  ║
    ╠═══════════════════╬═══════════════════╬═══════════════════╬═══════════════════════════════╣
    ║ Memory Limit      ║ 256MB-1GB (EPC)   ║ Full VM memory    ║ Up to 128 GB                  ║
    ╠═══════════════════╬═══════════════════╬═══════════════════╬═══════════════════════════════╣
    ║ Attestation       ║ DCAP/EPID         ║ AMD SEV-SNP APIs  ║ Nitro Security Module (NSM)   ║
    ╠═══════════════════╬═══════════════════╬═══════════════════╬═══════════════════════════════╣
    ║ Cloud Support     ║ Azure, Alibaba    ║ Azure, Google     ║ AWS Only                      ║
    ╠═══════════════════╬═══════════════════╬═══════════════════╬═══════════════════════════════╣
    ║ Trust Model       ║ Intel CPU only    ║ AMD CPU only      ║ AWS Nitro system              ║
    ╠═══════════════════╬═══════════════════╬═══════════════════╬═══════════════════════════════╣
    ║ Performance       ║ 5-15% overhead    ║ 2-5% overhead     ║ Minimal overhead              ║
    ╠═══════════════════╬═══════════════════╬═══════════════════╬═══════════════════════════════╣
    ║ Ease of Use       ║ Complex SDK       ║ Moderate          ║ Easiest (Docker-like)         ║
    ╠═══════════════════╬═══════════════════╬═══════════════════╬═══════════════════════════════╣
    ║ Side-Channel      ║ Most vulnerable   ║ More resistant    ║ Highly resistant              ║
    ║ Resistance        ║ (mitigations req) ║ (VM isolation)    ║ (Full VM isolation)           ║
    ╠═══════════════════╬═══════════════════╬═══════════════════╬═══════════════════════════════╣
    ║ Aethelred Use     ║ ✅ Primary        ║ ✅ Secondary      ║ ✅ Cloud deployment           ║
    ╚═══════════════════╩═══════════════════╩═══════════════════╩═══════════════════════════════╝
            "#.to_string(),
            detailed_differences: vec![
                TEEDifference {
                    feature: "Memory Model".to_string(),
                    platform_values: HashMap::from([
                        ("Intel SGX".to_string(), "Process-level enclave within application".to_string()),
                        ("AMD SEV-SNP".to_string(), "Full VM encryption with memory integrity".to_string()),
                        ("AWS Nitro".to_string(), "Isolated VM with dedicated resources".to_string()),
                    ]),
                    significance: "Affects scalability and development complexity".to_string(),
                },
                TEEDifference {
                    feature: "Root of Trust".to_string(),
                    platform_values: HashMap::from([
                        ("Intel SGX".to_string(), "Intel's attestation key hierarchy".to_string()),
                        ("AMD SEV-SNP".to_string(), "AMD's versioned chip endorsement key".to_string()),
                        ("AWS Nitro".to_string(), "AWS Nitro Security Module with PCR values".to_string()),
                    ]),
                    significance: "Determines who you're ultimately trusting".to_string(),
                },
            ],
            recommendations: vec![
                TEERecommendation {
                    use_case: "Financial AI with strict regulatory requirements".to_string(),
                    recommended: TEEPlatform::IntelSGX { version: 2, epc_size_mb: 256, flc_enabled: true },
                    reasoning: "Most mature attestation ecosystem, widely accepted by regulators".to_string(),
                },
                TEERecommendation {
                    use_case: "Large-scale ML inference".to_string(),
                    recommended: TEEPlatform::AWSNitro { vcpu_count: 4, memory_mb: 8192, nsm_version: "1.0".to_string() },
                    reasoning: "No memory limits, easy deployment, good for large models".to_string(),
                },
                TEERecommendation {
                    use_case: "On-premise deployment".to_string(),
                    recommended: TEEPlatform::AMDSEV { variant: SEVVariant::SEVSNP, asid_count: 509 },
                    reasoning: "Widely available in EPYC servers, full VM protection".to_string(),
                },
            ],
        }
    }
}

// ============================================================================
// Interactive Debugger Session
// ============================================================================

/// An interactive debugging session for understanding TEE operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEDebugSession {
    /// Session ID
    pub session_id: String,
    /// Platform being debugged
    pub platform: TEEPlatform,
    /// Current step in debugging
    pub current_step: DebugStep,
    /// Captured events
    pub events: Vec<TEEDebugEvent>,
    /// Breakpoints set
    pub breakpoints: Vec<TEEBreakpoint>,
    /// Memory watch points
    pub watch_points: Vec<MemoryWatchPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DebugStep {
    /// Before enclave entry
    PreEntry,
    /// During enclave initialization
    Initialization,
    /// Data decryption in progress
    Decryption,
    /// Model loading
    ModelLoading,
    /// Inference execution
    Inference,
    /// Attestation generation
    Attestation,
    /// Result sealing
    Sealing,
    /// Post enclave exit
    PostExit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEDebugEvent {
    /// Event timestamp
    pub timestamp: SystemTime,
    /// Event type
    pub event_type: DebugEventType,
    /// Event details
    pub details: String,
    /// ASCII visualization if applicable
    pub visualization: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DebugEventType {
    /// Memory read/write
    MemoryAccess { address: String, read: bool, encrypted: bool },
    /// Attestation-related
    Attestation { action: String },
    /// Crypto operation
    Crypto { operation: String, algorithm: String },
    /// Security boundary crossing
    BoundaryCrossing { direction: String },
    /// Enclave instruction
    EnclaveInstruction { instruction: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEBreakpoint {
    /// Breakpoint ID
    pub id: String,
    /// What to break on
    pub trigger: BreakpointTrigger,
    /// Is it enabled?
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BreakpointTrigger {
    /// Break on specific memory access
    MemoryAddress(String),
    /// Break on enclave instruction
    Instruction(String),
    /// Break on attestation operation
    Attestation,
    /// Break on crypto operation
    Crypto(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryWatchPoint {
    /// Watch point ID
    pub id: String,
    /// Memory region to watch
    pub region: String,
    /// Watch for reads, writes, or both
    pub watch_type: WatchType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WatchType {
    Read,
    Write,
    ReadWrite,
}

impl TEEDebugSession {
    /// Create a new debug session
    pub fn new(platform: TEEPlatform) -> Self {
        Self {
            session_id: uuid::Uuid::new_v4().to_string(),
            platform,
            current_step: DebugStep::PreEntry,
            events: Vec::new(),
            breakpoints: Vec::new(),
            watch_points: Vec::new(),
        }
    }

    /// Step through the next debugging stage
    pub fn step_next(&mut self) -> DebugStep {
        self.current_step = match self.current_step {
            DebugStep::PreEntry => DebugStep::Initialization,
            DebugStep::Initialization => DebugStep::Decryption,
            DebugStep::Decryption => DebugStep::ModelLoading,
            DebugStep::ModelLoading => DebugStep::Inference,
            DebugStep::Inference => DebugStep::Attestation,
            DebugStep::Attestation => DebugStep::Sealing,
            DebugStep::Sealing => DebugStep::PostExit,
            DebugStep::PostExit => DebugStep::PreEntry, // Wrap around
        };
        self.current_step.clone()
    }

    /// Add a breakpoint
    pub fn add_breakpoint(&mut self, trigger: BreakpointTrigger) -> String {
        let id = format!("bp_{}", self.breakpoints.len() + 1);
        self.breakpoints.push(TEEBreakpoint {
            id: id.clone(),
            trigger,
            enabled: true,
        });
        id
    }

    /// Get current step visualization
    pub fn visualize_current_step(&self) -> String {
        match self.current_step {
            DebugStep::PreEntry => r#"
    ┌─────────────────────────────────────────────────────────────┐
    │  🔍 DEBUG: PRE-ENTRY                                        │
    │                                                             │
    │  Status: Preparing to enter enclave                         │
    │                                                             │
    │  ┌─────────────────────────────────────────────────────┐   │
    │  │                    UNTRUSTED                        │   │
    │  │  📦 Encrypted data package ready                    │   │
    │  │  🔑 Session key established                         │   │
    │  │  📋 Enclave measurement verified                    │   │
    │  │                                                     │   │
    │  │          ▼ EENTER pending...                        │   │
    │  │  ═══════════════════════════════════════════════    │   │
    │  │  ║           ENCLAVE BOUNDARY                  ║    │   │
    │  │  ║                                             ║    │   │
    │  │  ║     [ Waiting for entry ]                   ║    │   │
    │  │  ║                                             ║    │   │
    │  │  ═══════════════════════════════════════════════    │   │
    │  └─────────────────────────────────────────────────────┘   │
    │                                                             │
    │  ▶ Press [Step] to enter enclave                           │
    └─────────────────────────────────────────────────────────────┘
            "#.to_string(),
            DebugStep::Initialization => r#"
    ┌─────────────────────────────────────────────────────────────┐
    │  🔍 DEBUG: INITIALIZATION                                   │
    │                                                             │
    │  Status: Inside enclave, initializing secure context        │
    │                                                             │
    │  ═══════════════════════════════════════════════════════   │
    │  ║           ENCLAVE (Active)                          ║   │
    │  ║                                                     ║   │
    │  ║  ✅ Enclave heap initialized                        ║   │
    │  ║  ✅ Trusted runtime loaded                          ║   │
    │  ║  ✅ Sealing key derived                             ║   │
    │  ║  ⏳ Loading encryption context...                    ║   │
    │  ║                                                     ║   │
    │  ║  Memory Layout:                                     ║   │
    │  ║  ┌─────────────────────────────────────────────┐   ║   │
    │  ║  │ 0x7000_0000 │ Heap (encrypted)              │   ║   │
    │  ║  │ 0x7010_0000 │ Stack (encrypted)             │   ║   │
    │  ║  │ 0x7020_0000 │ TCS (Thread Control)          │   ║   │
    │  ║  └─────────────────────────────────────────────┘   ║   │
    │  ║                                                     ║   │
    │  ═══════════════════════════════════════════════════════   │
    │                                                             │
    │  ▶ Press [Step] to begin decryption                        │
    └─────────────────────────────────────────────────────────────┘
            "#.to_string(),
            DebugStep::Decryption => r#"
    ┌─────────────────────────────────────────────────────────────┐
    │  🔍 DEBUG: DECRYPTION                                       │
    │                                                             │
    │  Status: Decrypting input data inside enclave              │
    │                                                             │
    │  ═══════════════════════════════════════════════════════   │
    │  ║           ENCLAVE (Decrypting)                      ║   │
    │  ║                                                     ║   │
    │  ║  Input Buffer (Before):                             ║   │
    │  ║  ┌─────────────────────────────────────────────┐   ║   │
    │  ║  │ 🔐 8f3a2b1c 9d4e5f6a 7b8c9d0e 1f2a3b4c    │   ║   │
    │  ║  │    a5b6c7d8 e9f0a1b2 c3d4e5f6 78901234    │   ║   │
    │  ║  └─────────────────────────────────────────────┘   ║   │
    │  ║                    ▼ AES-256-GCM                    ║   │
    │  ║  Output Buffer (After):                             ║   │
    │  ║  ┌─────────────────────────────────────────────┐   ║   │
    │  ║  │ 🔓 {"patient_id": "P12345",                 │   ║   │
    │  ║  │     "age": 45,                              │   ║   │
    │  ║  │     "lab_results": {...}}                   │   ║   │
    │  ║  └─────────────────────────────────────────────┘   ║   │
    │  ║                                                     ║   │
    │  ║  ✅ Decryption successful                           ║   │
    │  ║  ✅ HMAC verified (data integrity confirmed)        ║   │
    │  ║                                                     ║   │
    │  ═══════════════════════════════════════════════════════   │
    │                                                             │
    │  ⚠️ Plaintext is ONLY visible here, inside the enclave    │
    │  ▶ Press [Step] to load AI model                           │
    └─────────────────────────────────────────────────────────────┘
            "#.to_string(),
            DebugStep::ModelLoading => r#"
    ┌─────────────────────────────────────────────────────────────┐
    │  🔍 DEBUG: MODEL LOADING                                    │
    │                                                             │
    │  Status: Loading AI model weights into enclave             │
    │                                                             │
    │  ═══════════════════════════════════════════════════════   │
    │  ║           ENCLAVE (Loading Model)                   ║   │
    │  ║                                                     ║   │
    │  ║  Model: MedicalRisk-v2.onnx                         ║   │
    │  ║  ┌─────────────────────────────────────────────┐   ║   │
    │  ║  │ Loading layers...                           │   ║   │
    │  ║  │ ████████████████████████░░░░ 80%            │   ║   │
    │  ║  │                                             │   ║   │
    │  ║  │ Layer 1/12: Dense (128 units)      ✅      │   ║   │
    │  ║  │ Layer 2/12: ReLU                    ✅      │   ║   │
    │  ║  │ Layer 3/12: Dense (64 units)       ✅      │   ║   │
    │  ║  │ ...                                         │   ║   │
    │  ║  │ Layer 10/12: Dense (32 units)      ⏳      │   ║   │
    │  ║  └─────────────────────────────────────────────┘   ║   │
    │  ║                                                     ║   │
    │  ║  Model Hash: 0x7f8e9d0c1b2a3948...                 ║   │
    │  ║  ✅ Hash matches registered model                   ║   │
    │  ║                                                     ║   │
    │  ═══════════════════════════════════════════════════════   │
    │                                                             │
    │  ⚠️ Model weights are also protected inside enclave       │
    │  ▶ Press [Step] to run inference                           │
    └─────────────────────────────────────────────────────────────┘
            "#.to_string(),
            DebugStep::Inference => r#"
    ┌─────────────────────────────────────────────────────────────┐
    │  🔍 DEBUG: INFERENCE                                        │
    │                                                             │
    │  Status: Running AI inference on patient data              │
    │                                                             │
    │  ═══════════════════════════════════════════════════════   │
    │  ║           ENCLAVE (Computing)                       ║   │
    │  ║                                                     ║   │
    │  ║  ┌──────────────┐      ┌──────────────────────┐   ║   │
    │  ║  │ Patient Data │─────▶│    🧠 ONNX Runtime   │   ║   │
    │  ║  └──────────────┘      │                      │   ║   │
    │  ║                        │ Input:               │   ║   │
    │  ║                        │  age=45, A1C=6.2     │   ║   │
    │  ║                        │  BP=130/85, BMI=28   │   ║   │
    │  ║                        │                      │   ║   │
    │  ║                        │     ▼ Forward Pass   │   ║   │
    │  ║                        │                      │   ║   │
    │  ║                        │ Output:              │   ║   │
    │  ║                        │  risk_score: 0.23    │   ║   │
    │  ║                        │  category: LOW       │   ║   │
    │  ║                        │  confidence: 94.2%   │   ║   │
    │  ║                        └──────────────────────┘   ║   │
    │  ║                                                     ║   │
    │  ║  Computation time: 45.2ms                           ║   │
    │  ║  Memory peak: 12.3 MB                               ║   │
    │  ║                                                     ║   │
    │  ═══════════════════════════════════════════════════════   │
    │                                                             │
    │  ▶ Press [Step] to generate attestation                    │
    └─────────────────────────────────────────────────────────────┘
            "#.to_string(),
            DebugStep::Attestation => r#"
    ┌─────────────────────────────────────────────────────────────┐
    │  🔍 DEBUG: ATTESTATION                                      │
    │                                                             │
    │  Status: Generating cryptographic proof of execution       │
    │                                                             │
    │  ═══════════════════════════════════════════════════════   │
    │  ║           ENCLAVE (Attesting)                       ║   │
    │  ║                                                     ║   │
    │  ║  Generating EREPORT...                              ║   │
    │  ║  ┌─────────────────────────────────────────────┐   ║   │
    │  ║  │ MRENCLAVE:  0x7a3b9c2f1e8d...              │   ║   │
    │  ║  │ MRSIGNER:   0x4f2e1d0c9b8a...              │   ║   │
    │  ║  │ ISV_SVN:    3                               │   ║   │
    │  ║  │ ISV_PRODID: 1                               │   ║   │
    │  ║  │                                             │   ║   │
    │  ║  │ REPORT_DATA (User-defined):                 │   ║   │
    │  ║  │   Input Hash:  SHA256(patient_data)         │   ║   │
    │  ║  │   Output Hash: SHA256(risk_score)           │   ║   │
    │  ║  │   Model Hash:  SHA256(model_weights)        │   ║   │
    │  ║  └─────────────────────────────────────────────┘   ║   │
    │  ║                                                     ║   │
    │  ║  📜 Calling EGETKEY for signing...                 ║   │
    │  ║  ✅ Quote generated and signed                      ║   │
    │  ║                                                     ║   │
    │  ═══════════════════════════════════════════════════════   │
    │                                                             │
    │  This proof is signed by Intel hardware - unforgeable!     │
    │  ▶ Press [Step] to seal result                             │
    └─────────────────────────────────────────────────────────────┘
            "#.to_string(),
            DebugStep::Sealing => r#"
    ┌─────────────────────────────────────────────────────────────┐
    │  🔍 DEBUG: SEALING                                          │
    │                                                             │
    │  Status: Encrypting result for recipient                   │
    │                                                             │
    │  ═══════════════════════════════════════════════════════   │
    │  ║           ENCLAVE (Sealing)                         ║   │
    │  ║                                                     ║   │
    │  ║  Result (Plaintext):                                ║   │
    │  ║  ┌─────────────────────────────────────────────┐   ║   │
    │  ║  │ { "risk_score": 0.23,                       │   ║   │
    │  ║  │   "category": "LOW",                        │   ║   │
    │  ║  │   "confidence": 0.942 }                     │   ║   │
    │  ║  └─────────────────────────────────────────────┘   ║   │
    │  ║                    ▼ ECDH + AES-256                 ║   │
    │  ║  Sealed Result (Encrypted for recipient):           ║   │
    │  ║  ┌─────────────────────────────────────────────┐   ║   │
    │  ║  │ 🔐 9f8e7d6c 5b4a3928 1706f5e4 d3c2b1a0    │   ║   │
    │  ║  │    8796857 4635241 30291817 0615e4d3    │   ║   │
    │  ║  └─────────────────────────────────────────────┘   ║   │
    │  ║                                                     ║   │
    │  ║  ✅ Only recipient's private key can decrypt       ║   │
    │  ║                                                     ║   │
    │  ═══════════════════════════════════════════════════════   │
    │                                                             │
    │  ▶ Press [Step] to exit enclave                            │
    └─────────────────────────────────────────────────────────────┘
            "#.to_string(),
            DebugStep::PostExit => r#"
    ┌─────────────────────────────────────────────────────────────┐
    │  🔍 DEBUG: POST-EXIT                                        │
    │                                                             │
    │  Status: Enclave execution complete                        │
    │                                                             │
    │  ┌─────────────────────────────────────────────────────┐   │
    │  │                    UNTRUSTED                        │   │
    │  │                                                     │   │
    │  │  ═══════════════════════════════════════════════    │   │
    │  │  ║           ENCLAVE (Idle)                    ║    │   │
    │  │  ║    All sensitive data has been cleared      ║    │   │
    │  │  ═══════════════════════════════════════════════    │   │
    │  │          ▲ EEXIT completed                          │   │
    │  │                                                     │   │
    │  │  📦 Output Package:                                 │   │
    │  │  ┌─────────────────────────────────────────────┐   │   │
    │  │  │ 🔐 Sealed Result (only recipient can read)  │   │   │
    │  │  │ 📜 Attestation Quote (anyone can verify)    │   │   │
    │  │  │ 🏷️  Aethelred Digital Seal                  │   │   │
    │  │  └─────────────────────────────────────────────┘   │   │
    │  │                                                     │   │
    │  │  ✅ Computation verified by Intel SGX               │   │
    │  │  ✅ Result ready for on-chain commitment            │   │
    │  │  ✅ Bank can trust this AI decision                 │   │
    │  │                                                     │   │
    │  └─────────────────────────────────────────────────────┘   │
    │                                                             │
    │  ▶ Debug session complete. Press [Reset] to start over    │
    └─────────────────────────────────────────────────────────────┘
            "#.to_string(),
        }
    }
}

// ============================================================================
// Educational Quizzes
// ============================================================================

/// Educational quiz to test understanding of TEE concepts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEQuiz {
    /// Quiz title
    pub title: String,
    /// Difficulty level
    pub difficulty: QuizDifficulty,
    /// Questions
    pub questions: Vec<QuizQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuizDifficulty {
    Beginner,
    Intermediate,
    Advanced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuizQuestion {
    /// Question ID
    pub id: u32,
    /// The question
    pub question: String,
    /// Multiple choice options
    pub options: Vec<String>,
    /// Correct answer index
    pub correct_index: usize,
    /// Explanation of the answer
    pub explanation: String,
}

impl TEEQuiz {
    pub fn beginner_quiz() -> Self {
        TEEQuiz {
            title: "TEE Fundamentals Quiz".to_string(),
            difficulty: QuizDifficulty::Beginner,
            questions: vec![
                QuizQuestion {
                    id: 1,
                    question: "What does TEE stand for?".to_string(),
                    options: vec![
                        "Trusted Execution Environment".to_string(),
                        "Total Encryption Engine".to_string(),
                        "Temporary Enclave Executor".to_string(),
                        "Terminal Encryption Enclosure".to_string(),
                    ],
                    correct_index: 0,
                    explanation: "TEE stands for Trusted Execution Environment - a secure area \
                        of a processor that guarantees code and data loaded inside is protected \
                        with respect to confidentiality and integrity.".to_string(),
                },
                QuizQuestion {
                    id: 2,
                    question: "Who can read data inside an Intel SGX enclave?".to_string(),
                    options: vec![
                        "The operating system".to_string(),
                        "The cloud provider".to_string(),
                        "Only the enclave code itself".to_string(),
                        "Anyone with admin access".to_string(),
                    ],
                    correct_index: 2,
                    explanation: "Only the code running inside the enclave can access enclave memory. \
                        The OS, hypervisor, and even hardware debuggers cannot read enclave memory - \
                        this is enforced by the CPU hardware.".to_string(),
                },
                QuizQuestion {
                    id: 3,
                    question: "What is an attestation quote?".to_string(),
                    options: vec![
                        "A price quote for TEE hardware".to_string(),
                        "A cryptographic proof that code ran in a genuine TEE".to_string(),
                        "An error message from the enclave".to_string(),
                        "A performance benchmark result".to_string(),
                    ],
                    correct_index: 1,
                    explanation: "An attestation quote is a cryptographically signed proof from the \
                        CPU hardware that specific code ran inside a genuine TEE. It proves WHAT \
                        code ran, on WHAT inputs, and that it happened in authentic TEE hardware.".to_string(),
                },
                QuizQuestion {
                    id: 4,
                    question: "Why can banks trust AI decisions verified by TEE?".to_string(),
                    options: vec![
                        "Because TEEs are expensive".to_string(),
                        "Because the attestation is signed by unforgeable hardware keys".to_string(),
                        "Because the cloud provider says so".to_string(),
                        "Because TEEs run faster".to_string(),
                    ],
                    correct_index: 1,
                    explanation: "TEE attestations are signed by hardware keys that are fused into \
                        the CPU during manufacturing. Forging an attestation would require breaking \
                        the cryptographic signature or compromising Intel/AMD's root keys - \
                        both essentially impossible.".to_string(),
                },
            ],
        }
    }
}

// ============================================================================
// Main Debugger Interface
// ============================================================================

/// The main TEE Remote Attestation Debugger
pub struct TEERemoteAttestationDebugger {
    /// Current debug session
    pub session: Option<TEEDebugSession>,
    /// Attestation inspector
    pub inspector: AttestationInspector,
    /// Side-channel simulator
    pub side_channel_sim: SideChannelSimulator,
}

impl TEERemoteAttestationDebugger {
    pub fn new() -> Self {
        Self {
            session: None,
            inspector: AttestationInspector::new(),
            side_channel_sim: SideChannelSimulator,
        }
    }

    /// Start a new debug session
    pub fn start_session(&mut self, platform: TEEPlatform) -> &TEEDebugSession {
        self.session = Some(TEEDebugSession::new(platform));
        self.session.as_ref().unwrap()
    }

    /// Get the enclave journey visualization for a model
    pub fn visualize_journey(&self, model_name: &str) -> EnclaveJourney {
        let platform = self.session.as_ref()
            .map(|s| s.platform.clone())
            .unwrap_or(TEEPlatform::MockTEE { simulated_latency_ms: 100 });
        EnclaveJourney::ai_inference_journey(platform, model_name)
    }

    /// Inspect an attestation
    pub fn inspect_attestation(&self, quote: &[u8]) -> AttestationInspection {
        self.inspector.inspect_sgx_quote(quote)
    }

    /// Get memory boundary visualization
    pub fn visualize_memory_boundaries(&self) -> MemoryBoundaryVisualization {
        MemoryBoundaryVisualization::sgx_visualization()
    }

    /// Run a side-channel attack simulation
    pub fn simulate_attack(&self, attack: &str) -> Option<SideChannelSimulation> {
        match attack.to_lowercase().as_str() {
            "cache" | "prime+probe" => Some(SideChannelSimulator::simulate_cache_timing_attack()),
            "spectre" | "spectre-v1" => Some(SideChannelSimulator::simulate_spectre_attack()),
            _ => None,
        }
    }

    /// Get multi-TEE comparison
    pub fn compare_tees(&self) -> TEEComparison {
        TEEComparison::full_comparison()
    }

    /// Get educational quiz
    pub fn get_quiz(&self, level: QuizDifficulty) -> TEEQuiz {
        match level {
            QuizDifficulty::Beginner => TEEQuiz::beginner_quiz(),
            _ => TEEQuiz::beginner_quiz(), // TODO: Add more levels
        }
    }

    /// Print the debugger welcome message
    pub fn welcome_message(&self) -> String {
        r#"
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                               ║
    ║     ████████╗███████╗███████╗    ██████╗ ███████╗██████╗ ██╗   ██╗ ██████╗   ║
    ║     ╚══██╔══╝██╔════╝██╔════╝    ██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝   ║
    ║        ██║   █████╗  █████╗      ██║  ██║█████╗  ██████╔╝██║   ██║██║  ███╗  ║
    ║        ██║   ██╔══╝  ██╔══╝      ██║  ██║██╔══╝  ██╔══██╗██║   ██║██║   ██║  ║
    ║        ██║   ███████╗███████╗    ██████╔╝███████╗██████╔╝╚██████╔╝╚██████╔╝  ║
    ║        ╚═╝   ╚══════╝╚══════╝    ╚═════╝ ╚══════╝╚═════╝  ╚═════╝  ╚═════╝   ║
    ║                                                                               ║
    ║            REMOTE ATTESTATION DEBUGGER - Demystifying the Black Box           ║
    ║                                                                               ║
    ╠═══════════════════════════════════════════════════════════════════════════════╣
    ║                                                                               ║
    ║  Welcome to the Aethelred TEE Remote Attestation Debugger!                    ║
    ║                                                                               ║
    ║  This tool helps you understand EXACTLY what happens inside a Trusted        ║
    ║  Execution Environment. Perfect for developers who are new to TEEs.          ║
    ║                                                                               ║
    ║  FEATURES:                                                                    ║
    ║  ┌─────────────────────────────────────────────────────────────────────┐     ║
    ║  │  🎯 Enclave Journey    - Step-by-step data flow visualization      │     ║
    ║  │  🔍 Attestation Inspect - Decode and explain attestation quotes    │     ║
    ║  │  🧱 Memory Visualizer  - See encrypted/unencrypted boundaries      │     ║
    ║  │  ⚔️  Attack Simulator   - Understand why TEEs resist side-channels │     ║
    ║  │  📊 TEE Comparison     - Compare Intel SGX vs AMD SEV vs Nitro     │     ║
    ║  │  📝 Educational Quiz   - Test your understanding                   │     ║
    ║  └─────────────────────────────────────────────────────────────────────┘     ║
    ║                                                                               ║
    ║  GET STARTED:                                                                 ║
    ║    1. Select a TEE platform (Intel SGX, AMD SEV, or AWS Nitro)               ║
    ║    2. Choose a visualization mode                                             ║
    ║    3. Step through the enclave journey                                        ║
    ║                                                                               ║
    ║  After this tutorial, you'll understand:                                      ║
    ║    ✓ How data flows through a TEE                                            ║
    ║    ✓ What attestation proves and doesn't prove                               ║
    ║    ✓ Why banks can trust TEE-verified AI                                     ║
    ║    ✓ How to debug your own TEE applications                                  ║
    ║                                                                               ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝
        "#.to_string()
    }
}

impl Default for TEERemoteAttestationDebugger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enclave_journey_creation() {
        let journey = EnclaveJourney::ai_inference_journey(
            TEEPlatform::IntelSGX { version: 2, epc_size_mb: 256, flc_enabled: true },
            "MedicalRisk-v2"
        );

        assert!(!journey.journey_id.is_empty());
        assert_eq!(journey.steps.len(), 6);
        assert!(journey.total_duration > Duration::from_secs(0));
    }

    #[test]
    fn test_attestation_inspection() {
        let inspector = AttestationInspector::new();
        let mock_quote = vec![0x00, 0x03, 0x00, 0x02]; // Minimal mock
        let inspection = inspector.inspect_sgx_quote(&mock_quote);

        assert!(!inspection.fields.is_empty());
        assert!(!inspection.proves.is_empty());
        assert!(!inspection.does_not_prove.is_empty());
    }

    #[test]
    fn test_debug_session() {
        let mut debugger = TEERemoteAttestationDebugger::new();
        let session = debugger.start_session(TEEPlatform::MockTEE { simulated_latency_ms: 50 });

        assert!(!session.session_id.is_empty());
        assert!(matches!(session.current_step, DebugStep::PreEntry));
    }

    #[test]
    fn test_side_channel_simulation() {
        let cache_attack = SideChannelSimulator::simulate_cache_timing_attack();
        assert!(cache_attack.mitigated);

        let spectre_attack = SideChannelSimulator::simulate_spectre_attack();
        assert!(spectre_attack.mitigated);
    }

    #[test]
    fn test_tee_comparison() {
        let comparison = TEEComparison::full_comparison();
        assert_eq!(comparison.platforms.len(), 3);
        assert!(!comparison.recommendations.is_empty());
    }

    #[test]
    fn test_quiz() {
        let quiz = TEEQuiz::beginner_quiz();
        assert!(!quiz.questions.is_empty());

        for question in &quiz.questions {
            assert!(question.correct_index < question.options.len());
        }
    }
}
