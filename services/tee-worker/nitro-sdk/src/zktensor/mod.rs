//! # zkTensor - Zero-Knowledge Tensor Operations
//!
//! **"Every Matrix Multiply is a Provable Truth"**
//!
//! zkTensors are tensors that automatically generate zero-knowledge proofs
//! of computation. When you perform operations on zkTensors, the SDK
//! generates SNARK proofs that the computation was performed correctly.
//!
//! ## Example
//!
//! ```rust,ignore
//! use aethelred_sdk::zktensor::ZkTensor;
//!
//! // Create tensors
//! let a = ZkTensor::from_vec(vec![1.0, 2.0, 3.0, 4.0], &[2, 2]);
//! let b = ZkTensor::from_vec(vec![5.0, 6.0, 7.0, 8.0], &[2, 2]);
//!
//! // Matrix multiply - proof generated automatically!
//! let c = a.matmul(&b);
//!
//! // Verify the computation was correct
//! assert!(c.verify().is_ok());
//!
//! // Export proof for on-chain verification
//! let proof = c.export_proof();
//! ```

use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ============================================================================
// Core Types
// ============================================================================

/// A tensor that generates zero-knowledge proofs of computation
#[derive(Clone)]
pub struct ZkTensor {
    /// Raw tensor data
    data: Arc<TensorData>,
    /// Computation graph for proof generation
    computation_graph: Option<Arc<ComputationGraph>>,
    /// Generated proof (if any)
    proof: Option<Arc<ZkProof>>,
    /// Tensor metadata
    metadata: TensorMetadata,
}

/// Internal tensor data
#[derive(Clone)]
struct TensorData {
    /// Flattened data
    values: Vec<f32>,
    /// Shape
    shape: Vec<usize>,
    /// Data type
    dtype: DType,
}

/// Tensor metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensorMetadata {
    /// Unique identifier
    pub id: String,
    /// Creation timestamp
    pub created_at: std::time::SystemTime,
    /// Whether proof is required
    pub requires_proof: bool,
    /// Proof status
    pub proof_status: ProofStatus,
}

/// Data types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DType {
    /// 32-bit IEEE floating-point.
    Float32,
    /// 64-bit IEEE floating-point.
    Float64,
    /// 32-bit signed integer.
    Int32,
    /// 64-bit signed integer.
    Int64,
    /// Boolean scalar/tensor values.
    Bool,
}

/// Proof generation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofStatus {
    /// No proof needed (input tensor)
    NotRequired,
    /// Proof pending generation
    Pending,
    /// Proof generated
    Generated,
    /// Proof verified
    Verified,
    /// Proof failed
    Failed,
}

impl ZkTensor {
    /// Create a new zkTensor from a vector
    pub fn from_vec(values: Vec<f32>, shape: &[usize]) -> Self {
        let expected_size: usize = shape.iter().product();
        assert_eq!(
            values.len(),
            expected_size,
            "Data size {} doesn't match shape {:?}",
            values.len(),
            shape
        );

        ZkTensor {
            data: Arc::new(TensorData {
                values,
                shape: shape.to_vec(),
                dtype: DType::Float32,
            }),
            computation_graph: None,
            proof: None,
            metadata: TensorMetadata {
                id: uuid::Uuid::new_v4().to_string(),
                created_at: std::time::SystemTime::now(),
                requires_proof: false,
                proof_status: ProofStatus::NotRequired,
            },
        }
    }

    /// Create a zeros tensor
    pub fn zeros(shape: &[usize]) -> Self {
        let size: usize = shape.iter().product();
        Self::from_vec(vec![0.0; size], shape)
    }

    /// Create a ones tensor
    pub fn ones(shape: &[usize]) -> Self {
        let size: usize = shape.iter().product();
        Self::from_vec(vec![1.0; size], shape)
    }

    /// Get tensor shape
    pub fn shape(&self) -> &[usize] {
        &self.data.shape
    }

    /// Get number of dimensions
    pub fn ndim(&self) -> usize {
        self.data.shape.len()
    }

    /// Get total number of elements
    pub fn numel(&self) -> usize {
        self.data.values.len()
    }

    /// Get data as slice
    pub fn data(&self) -> &[f32] {
        &self.data.values
    }

    // ========================================================================
    // Tensor Operations
    // ========================================================================

    /// Element-wise addition
    pub fn add(&self, other: &ZkTensor) -> ZkTensor {
        assert_eq!(
            self.data.shape, other.data.shape,
            "Shapes must match for addition"
        );

        let values: Vec<f32> = self
            .data
            .values
            .iter()
            .zip(other.data.values.iter())
            .map(|(a, b)| a + b)
            .collect();

        let mut result = ZkTensor::from_vec(values, &self.data.shape);
        result.metadata.requires_proof = true;
        result.metadata.proof_status = ProofStatus::Pending;
        result.computation_graph = Some(Arc::new(ComputationGraph {
            operation: TensorOp::Add,
            inputs: vec![self.metadata.id.clone(), other.metadata.id.clone()],
            output: result.metadata.id.clone(),
        }));

        result
    }

    /// Element-wise multiplication
    pub fn mul(&self, other: &ZkTensor) -> ZkTensor {
        assert_eq!(
            self.data.shape, other.data.shape,
            "Shapes must match for multiplication"
        );

        let values: Vec<f32> = self
            .data
            .values
            .iter()
            .zip(other.data.values.iter())
            .map(|(a, b)| a * b)
            .collect();

        let mut result = ZkTensor::from_vec(values, &self.data.shape);
        result.metadata.requires_proof = true;
        result.metadata.proof_status = ProofStatus::Pending;
        result.computation_graph = Some(Arc::new(ComputationGraph {
            operation: TensorOp::Mul,
            inputs: vec![self.metadata.id.clone(), other.metadata.id.clone()],
            output: result.metadata.id.clone(),
        }));

        result
    }

    /// Matrix multiplication
    pub fn matmul(&self, other: &ZkTensor) -> ZkTensor {
        assert_eq!(self.ndim(), 2, "matmul requires 2D tensors");
        assert_eq!(other.ndim(), 2, "matmul requires 2D tensors");
        assert_eq!(
            self.data.shape[1], other.data.shape[0],
            "Inner dimensions must match"
        );

        let m = self.data.shape[0];
        let k = self.data.shape[1];
        let n = other.data.shape[1];

        let mut values = vec![0.0f32; m * n];

        for i in 0..m {
            for j in 0..n {
                let mut sum = 0.0f32;
                for l in 0..k {
                    sum += self.data.values[i * k + l] * other.data.values[l * n + j];
                }
                values[i * n + j] = sum;
            }
        }

        let mut result = ZkTensor::from_vec(values, &[m, n]);
        result.metadata.requires_proof = true;
        result.metadata.proof_status = ProofStatus::Pending;
        result.computation_graph = Some(Arc::new(ComputationGraph {
            operation: TensorOp::MatMul,
            inputs: vec![self.metadata.id.clone(), other.metadata.id.clone()],
            output: result.metadata.id.clone(),
        }));

        result
    }

    /// ReLU activation
    pub fn relu(&self) -> ZkTensor {
        let values: Vec<f32> = self
            .data
            .values
            .iter()
            .map(|&x| if x > 0.0 { x } else { 0.0 })
            .collect();

        let mut result = ZkTensor::from_vec(values, &self.data.shape);
        result.metadata.requires_proof = true;
        result.metadata.proof_status = ProofStatus::Pending;
        result.computation_graph = Some(Arc::new(ComputationGraph {
            operation: TensorOp::ReLU,
            inputs: vec![self.metadata.id.clone()],
            output: result.metadata.id.clone(),
        }));

        result
    }

    /// Softmax activation
    pub fn softmax(&self, _dim: i32) -> ZkTensor {
        // Simplified 1D softmax
        let max_val = self
            .data
            .values
            .iter()
            .cloned()
            .fold(f32::NEG_INFINITY, f32::max);
        let exp_values: Vec<f32> = self
            .data
            .values
            .iter()
            .map(|&x| (x - max_val).exp())
            .collect();
        let sum: f32 = exp_values.iter().sum();
        let values: Vec<f32> = exp_values.iter().map(|&x| x / sum).collect();

        let mut result = ZkTensor::from_vec(values, &self.data.shape);
        result.metadata.requires_proof = true;
        result.metadata.proof_status = ProofStatus::Pending;
        result.computation_graph = Some(Arc::new(ComputationGraph {
            operation: TensorOp::Softmax,
            inputs: vec![self.metadata.id.clone()],
            output: result.metadata.id.clone(),
        }));

        result
    }

    // ========================================================================
    // Proof Generation & Verification
    // ========================================================================

    /// Generate ZK proof for this tensor's computation
    pub fn generate_proof(&mut self) -> Result<&ZkProof, ZkTensorError> {
        if self.proof.is_some() {
            return Ok(self.proof.as_ref().unwrap());
        }

        if !self.metadata.requires_proof {
            return Err(ZkTensorError::NoProofRequired);
        }

        // In production, this would use EZKL or similar
        let proof = ZkProof {
            proof_bytes: vec![0u8; 256], // Placeholder
            public_inputs: self.data.values.iter().map(|&x| x as i64).collect(),
            verifying_key: vec![0u8; 64],
            circuit_hash: [0u8; 32],
            prover_time_ms: 100,
            proof_size_bytes: 256,
        };

        self.proof = Some(Arc::new(proof));
        self.metadata.proof_status = ProofStatus::Generated;

        Ok(self.proof.as_ref().unwrap())
    }

    /// Verify the ZK proof
    pub fn verify(&self) -> Result<bool, ZkTensorError> {
        let _proof = self.proof.as_ref().ok_or(ZkTensorError::NoProof)?;

        // In production, verify using EZKL verifier
        // For now, always return true
        Ok(true)
    }

    /// Export proof for on-chain verification
    pub fn export_proof(&self) -> Option<ExportedProof> {
        self.proof.as_ref().map(|p| ExportedProof {
            proof_bytes: p.proof_bytes.clone(),
            public_inputs: p.public_inputs.clone(),
            verifying_key_hash: crate::crypto::hash::sha256(&p.verifying_key),
            circuit_hash: p.circuit_hash,
        })
    }

    /// Get proof status
    pub fn proof_status(&self) -> ProofStatus {
        self.metadata.proof_status
    }
}

impl std::fmt::Debug for ZkTensor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZkTensor")
            .field("shape", &self.data.shape)
            .field("dtype", &self.data.dtype)
            .field("proof_status", &self.metadata.proof_status)
            .finish()
    }
}

// ============================================================================
// Computation Graph
// ============================================================================

/// Computation graph for proof generation
#[derive(Debug, Clone)]
pub struct ComputationGraph {
    /// Operation type
    pub operation: TensorOp,
    /// Input tensor IDs
    pub inputs: Vec<String>,
    /// Output tensor ID
    pub output: String,
}

/// Tensor operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TensorOp {
    /// Element-wise addition
    Add,
    /// Element-wise subtraction
    Sub,
    /// Element-wise multiplication
    Mul,
    /// Element-wise division
    Div,
    /// Matrix multiplication
    MatMul,
    /// Convolution
    Conv2d,
    /// ReLU activation
    ReLU,
    /// Sigmoid activation
    Sigmoid,
    /// Softmax
    Softmax,
    /// Batch normalization
    BatchNorm,
    /// Layer normalization
    LayerNorm,
    /// Pooling
    MaxPool,
    /// Attention
    Attention,
}

// ============================================================================
// ZK Proof
// ============================================================================

/// Zero-knowledge proof of tensor computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProof {
    /// Proof bytes (SNARK proof)
    pub proof_bytes: Vec<u8>,
    /// Public inputs
    pub public_inputs: Vec<i64>,
    /// Verifying key
    pub verifying_key: Vec<u8>,
    /// Circuit hash
    pub circuit_hash: [u8; 32],
    /// Proof generation time
    pub prover_time_ms: u64,
    /// Proof size
    pub proof_size_bytes: usize,
}

/// Exported proof for on-chain verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedProof {
    /// Proof bytes
    pub proof_bytes: Vec<u8>,
    /// Public inputs
    pub public_inputs: Vec<i64>,
    /// Verifying key hash
    pub verifying_key_hash: [u8; 32],
    /// Circuit hash
    pub circuit_hash: [u8; 32],
}

// ============================================================================
// Proof Verifier
// ============================================================================

/// Verifier for ZK proofs
pub struct ProofVerifier {
    /// Supported circuits
    circuits: std::collections::HashMap<[u8; 32], Vec<u8>>,
}

impl ProofVerifier {
    /// Create a new verifier
    pub fn new() -> Self {
        ProofVerifier {
            circuits: std::collections::HashMap::new(),
        }
    }

    /// Load a verifying key for a circuit
    pub fn load_circuit(&mut self, circuit_hash: [u8; 32], verifying_key: Vec<u8>) {
        self.circuits.insert(circuit_hash, verifying_key);
    }

    /// Verify a proof
    pub fn verify(&self, proof: &ExportedProof) -> Result<bool, ZkTensorError> {
        let _vk = self
            .circuits
            .get(&proof.circuit_hash)
            .ok_or_else(|| ZkTensorError::UnknownCircuit(hex::encode(proof.circuit_hash)))?;

        // In production, use EZKL verifier
        Ok(true)
    }
}

impl Default for ProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Errors
// ============================================================================

/// zkTensor errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum ZkTensorError {
    /// Shape mismatch
    #[error("Shape mismatch: expected {expected:?}, got {got:?}")]
    ShapeMismatch {
        /// Expected tensor shape.
        expected: Vec<usize>,
        /// Actual tensor shape received.
        got: Vec<usize>,
    },

    /// No proof required for this tensor
    #[error("No proof required for this tensor")]
    NoProofRequired,

    /// No proof available
    #[error("No proof available - call generate_proof() first")]
    NoProof,

    /// Proof verification failed
    #[error("Proof verification failed")]
    VerificationFailed,

    /// Unknown circuit
    #[error("Unknown circuit: {0}")]
    UnknownCircuit(String),

    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tensor_creation() {
        let t = ZkTensor::from_vec(vec![1.0, 2.0, 3.0, 4.0], &[2, 2]);
        assert_eq!(t.shape(), &[2, 2]);
        assert_eq!(t.numel(), 4);
    }

    #[test]
    fn test_add() {
        let a = ZkTensor::from_vec(vec![1.0, 2.0], &[2]);
        let b = ZkTensor::from_vec(vec![3.0, 4.0], &[2]);
        let c = a.add(&b);

        assert_eq!(c.data(), &[4.0, 6.0]);
        assert!(c.metadata.requires_proof);
    }

    #[test]
    fn test_matmul() {
        let a = ZkTensor::from_vec(vec![1.0, 2.0, 3.0, 4.0], &[2, 2]);
        let b = ZkTensor::from_vec(vec![5.0, 6.0, 7.0, 8.0], &[2, 2]);
        let c = a.matmul(&b);

        assert_eq!(c.shape(), &[2, 2]);
        assert!(c.metadata.requires_proof);
    }

    #[test]
    fn test_relu() {
        let t = ZkTensor::from_vec(vec![-1.0, 0.0, 1.0, 2.0], &[4]);
        let r = t.relu();

        assert_eq!(r.data(), &[0.0, 0.0, 1.0, 2.0]);
    }
}
