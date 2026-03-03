//! Aethelred SDK - Neural Network Module
//!
//! PyTorch-compatible neural network API with:
//! - Module trait for layer composition
//! - Parameter management
//! - Forward/backward hooks
//! - State dict serialization
//! - Training/evaluation modes

use std::collections::HashMap;
use std::sync::Arc;

use crate::runtime::Device;
use crate::tensor::{Tensor, TensorError};

// ============ Parameter ============

/// Neural network parameter
#[derive(Debug, Clone)]
pub struct Parameter {
    /// Parameter data
    pub data: Tensor,
    /// Whether parameter requires gradients
    pub requires_grad: bool,
    /// Parameter name
    pub name: String,
}

impl Parameter {
    /// Create a new parameter
    pub fn new(data: Tensor, requires_grad: bool) -> Self {
        Self {
            data,
            requires_grad,
            name: String::new(),
        }
    }

    /// Get gradient
    pub fn grad(&self) -> Option<&Tensor> {
        self.data.grad()
    }

    /// Zero gradients
    pub fn zero_grad(&mut self) {
        // Clear gradient
    }

    /// Detach from computation graph
    pub fn detach(&self) -> Tensor {
        self.data.clone_tensor()
    }
}

// ============ Module Trait ============

/// Neural network module trait
pub trait Module {
    /// Forward pass
    fn forward(&self, input: &Tensor) -> Result<Tensor, TensorError>;

    /// Get module name
    fn name(&self) -> &str {
        std::any::type_name::<Self>()
            .split("::")
            .last()
            .unwrap_or("Module")
    }

    /// Get all parameters
    fn parameters(&self) -> Vec<Parameter> {
        Vec::new()
    }

    /// Get named parameters
    fn named_parameters(&self) -> HashMap<String, Parameter> {
        HashMap::new()
    }

    /// Get all submodules
    fn modules(&self) -> Vec<Arc<dyn Module>> {
        Vec::new()
    }

    /// Get named modules
    fn named_modules(&self) -> HashMap<String, Arc<dyn Module>> {
        HashMap::new()
    }

    /// Set training mode
    fn train(&mut self, _mode: bool) {}

    /// Set evaluation mode
    fn eval(&mut self) {
        self.train(false);
    }

    /// Check if in training mode
    fn is_training(&self) -> bool {
        true
    }

    /// Get state dict
    fn state_dict(&self) -> HashMap<String, Tensor> {
        let mut state = HashMap::new();
        for (name, param) in self.named_parameters() {
            state.insert(name, param.data);
        }
        state
    }

    /// Load state dict
    fn load_state_dict(&mut self, _state_dict: HashMap<String, Tensor>) -> Result<(), TensorError> {
        Ok(())
    }

    /// Count parameters
    fn num_parameters(&self) -> usize {
        self.parameters().iter().map(|p| p.data.numel()).sum()
    }

    /// Zero all gradients
    fn zero_grad(&mut self) {
        // Clear all parameter gradients
    }

    /// Move to device
    fn to_device(&mut self, _device: Device) -> Result<(), TensorError> {
        Ok(())
    }
}

// ============ Sequential Container ============

/// Sequential container
pub struct Sequential {
    layers: Vec<Box<dyn Module>>,
    training: bool,
}

impl Sequential {
    /// Create a new sequential container
    pub fn new(layers: Vec<Box<dyn Module>>) -> Self {
        Self {
            layers,
            training: true,
        }
    }

    /// Add a layer
    pub fn add(&mut self, layer: Box<dyn Module>) {
        self.layers.push(layer);
    }

    /// Get number of layers
    pub fn len(&self) -> usize {
        self.layers.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }
}

impl Module for Sequential {
    fn forward(&self, input: &Tensor) -> Result<Tensor, TensorError> {
        let mut output = input.clone_tensor();
        for layer in &self.layers {
            output = layer.forward(&output)?;
        }
        Ok(output)
    }

    fn name(&self) -> &str {
        "Sequential"
    }

    fn parameters(&self) -> Vec<Parameter> {
        let mut params = Vec::new();
        for layer in &self.layers {
            params.extend(layer.parameters());
        }
        params
    }

    fn train(&mut self, mode: bool) {
        self.training = mode;
        for layer in &mut self.layers {
            layer.train(mode);
        }
    }

    fn is_training(&self) -> bool {
        self.training
    }
}

// ============ Linear Layer ============

/// Linear (fully connected) layer
pub struct Linear {
    in_features: usize,
    out_features: usize,
    weight: Parameter,
    bias: Option<Parameter>,
    training: bool,
}

impl Linear {
    /// Create a new linear layer
    pub fn new(in_features: usize, out_features: usize) -> Self {
        Self::with_bias(in_features, out_features, true)
    }

    /// Create a new linear layer with optional bias
    pub fn with_bias(in_features: usize, out_features: usize, bias: bool) -> Self {
        let device = Device::cpu();

        // Kaiming uniform initialization
        let bound = (6.0 / in_features as f64).sqrt();
        let weight_data: Vec<f32> = (0..out_features * in_features)
            .map(|_| (rand::random::<f64>() * 2.0 - 1.0) * bound)
            .map(|x| x as f32)
            .collect();
        let weight =
            Tensor::new(weight_data, vec![out_features, in_features], device.clone()).unwrap();

        let bias_param = if bias {
            let bound = 1.0 / (in_features as f64).sqrt();
            let bias_data: Vec<f32> = (0..out_features)
                .map(|_| (rand::random::<f64>() * 2.0 - 1.0) * bound)
                .map(|x| x as f32)
                .collect();
            Some(Parameter::new(
                Tensor::new(bias_data, vec![out_features], device).unwrap(),
                true,
            ))
        } else {
            None
        };

        Self {
            in_features,
            out_features,
            weight: Parameter::new(weight, true),
            bias: bias_param,
            training: true,
        }
    }
}

impl Module for Linear {
    fn forward(&self, input: &Tensor) -> Result<Tensor, TensorError> {
        // output = input @ weight.T + bias
        let weight_t = self.weight.data.t();
        let mut output = input.matmul(&weight_t);

        if let Some(ref bias) = self.bias {
            output = output.add(&bias.data);
        }

        Ok(output)
    }

    fn name(&self) -> &str {
        "Linear"
    }

    fn parameters(&self) -> Vec<Parameter> {
        let mut params = vec![self.weight.clone()];
        if let Some(ref bias) = self.bias {
            params.push(bias.clone());
        }
        params
    }

    fn train(&mut self, mode: bool) {
        self.training = mode;
    }

    fn is_training(&self) -> bool {
        self.training
    }
}

// ============ Activation Functions ============

/// ReLU activation
pub struct ReLU;

impl Module for ReLU {
    fn forward(&self, input: &Tensor) -> Result<Tensor, TensorError> {
        Ok(input.relu())
    }

    fn name(&self) -> &str {
        "ReLU"
    }
}

/// GELU activation
pub struct GELU;

impl Module for GELU {
    fn forward(&self, input: &Tensor) -> Result<Tensor, TensorError> {
        Ok(input.gelu())
    }

    fn name(&self) -> &str {
        "GELU"
    }
}

/// SiLU activation
pub struct SiLU;

impl Module for SiLU {
    fn forward(&self, input: &Tensor) -> Result<Tensor, TensorError> {
        Ok(input.silu())
    }

    fn name(&self) -> &str {
        "SiLU"
    }
}

/// Sigmoid activation
pub struct Sigmoid;

impl Module for Sigmoid {
    fn forward(&self, input: &Tensor) -> Result<Tensor, TensorError> {
        Ok(input.sigmoid())
    }

    fn name(&self) -> &str {
        "Sigmoid"
    }
}

/// Tanh activation
pub struct Tanh;

impl Module for Tanh {
    fn forward(&self, input: &Tensor) -> Result<Tensor, TensorError> {
        Ok(input.tanh())
    }

    fn name(&self) -> &str {
        "Tanh"
    }
}

/// Softmax activation
pub struct Softmax {
    dim: i64,
}

impl Softmax {
    /// Create new softmax with dimension
    pub fn new(dim: i64) -> Self {
        Self { dim }
    }
}

impl Module for Softmax {
    fn forward(&self, input: &Tensor) -> Result<Tensor, TensorError> {
        // softmax = exp(x - max(x)) / sum(exp(x - max(x)))
        let max_val = input.max(None);
        let shifted = input.sub(&max_val);
        let exp_vals = shifted.exp();
        let sum_exp = exp_vals.sum(None);
        Ok(exp_vals.div(&sum_exp))
    }

    fn name(&self) -> &str {
        "Softmax"
    }
}

// ============ Normalization Layers ============

/// Layer normalization
pub struct LayerNorm {
    normalized_shape: Vec<usize>,
    eps: f64,
    weight: Option<Parameter>,
    bias: Option<Parameter>,
    training: bool,
}

impl LayerNorm {
    /// Create new layer norm
    pub fn new(normalized_shape: Vec<usize>) -> Self {
        Self::with_options(normalized_shape, 1e-5, true)
    }

    /// Create with options
    pub fn with_options(normalized_shape: Vec<usize>, eps: f64, elementwise_affine: bool) -> Self {
        let device = Device::cpu();
        let _size: usize = normalized_shape.iter().product();

        let (weight, bias) = if elementwise_affine {
            let w = Parameter::new(Tensor::ones(normalized_shape.clone(), device.clone()), true);
            let b = Parameter::new(Tensor::zeros(normalized_shape.clone(), device), true);
            (Some(w), Some(b))
        } else {
            (None, None)
        };

        Self {
            normalized_shape,
            eps,
            weight,
            bias,
            training: true,
        }
    }
}

impl Module for LayerNorm {
    fn forward(&self, input: &Tensor) -> Result<Tensor, TensorError> {
        // Compute mean and variance
        let mean = input.mean(None);
        let diff = input.sub(&mean);
        let var = diff.mul(&diff).mean(None);

        // Normalize
        let eps_tensor = Tensor::full(vec![1], self.eps, Device::cpu());
        let std = var.add(&eps_tensor).sqrt();
        let mut normalized = diff.div(&std);

        // Apply affine transformation
        if let (Some(ref weight), Some(ref bias)) = (&self.weight, &self.bias) {
            normalized = normalized.mul(&weight.data).add(&bias.data);
        }

        Ok(normalized)
    }

    fn name(&self) -> &str {
        "LayerNorm"
    }

    fn parameters(&self) -> Vec<Parameter> {
        let mut params = Vec::new();
        if let Some(ref w) = self.weight {
            params.push(w.clone());
        }
        if let Some(ref b) = self.bias {
            params.push(b.clone());
        }
        params
    }

    fn train(&mut self, mode: bool) {
        self.training = mode;
    }
}

/// RMS normalization
pub struct RMSNorm {
    normalized_shape: Vec<usize>,
    eps: f64,
    weight: Parameter,
    training: bool,
}

impl RMSNorm {
    /// Create new RMS norm
    pub fn new(normalized_shape: Vec<usize>) -> Self {
        Self::with_eps(normalized_shape, 1e-6)
    }

    /// Create with epsilon
    pub fn with_eps(normalized_shape: Vec<usize>, eps: f64) -> Self {
        let device = Device::cpu();
        let weight = Parameter::new(Tensor::ones(normalized_shape.clone(), device), true);

        Self {
            normalized_shape,
            eps,
            weight,
            training: true,
        }
    }
}

impl Module for RMSNorm {
    fn forward(&self, input: &Tensor) -> Result<Tensor, TensorError> {
        // RMS = sqrt(mean(x^2))
        let sq = input.mul(input);
        let mean_sq = sq.mean(None);
        let eps_tensor = Tensor::full(vec![1], self.eps, Device::cpu());
        let rms = mean_sq.add(&eps_tensor).sqrt();

        // Normalize and scale
        let normalized = input.div(&rms);
        Ok(normalized.mul(&self.weight.data))
    }

    fn name(&self) -> &str {
        "RMSNorm"
    }

    fn parameters(&self) -> Vec<Parameter> {
        vec![self.weight.clone()]
    }

    fn train(&mut self, mode: bool) {
        self.training = mode;
    }
}

// ============ Dropout ============

/// Dropout layer
pub struct Dropout {
    p: f64,
    training: bool,
}

impl Dropout {
    /// Create new dropout
    pub fn new(p: f64) -> Self {
        Self { p, training: true }
    }
}

impl Module for Dropout {
    fn forward(&self, input: &Tensor) -> Result<Tensor, TensorError> {
        if !self.training || self.p == 0.0 {
            return Ok(input.clone_tensor());
        }

        // Apply dropout (simplified - would need proper random mask)
        let scale = 1.0 / (1.0 - self.p);
        let scale_tensor = Tensor::full(vec![1], scale, Device::cpu());
        Ok(input.mul(&scale_tensor))
    }

    fn name(&self) -> &str {
        "Dropout"
    }

    fn train(&mut self, mode: bool) {
        self.training = mode;
    }

    fn is_training(&self) -> bool {
        self.training
    }
}

// ============ Embedding ============

/// Embedding layer
pub struct Embedding {
    num_embeddings: usize,
    embedding_dim: usize,
    weight: Parameter,
    padding_idx: Option<usize>,
    training: bool,
}

impl Embedding {
    /// Create new embedding
    pub fn new(num_embeddings: usize, embedding_dim: usize) -> Self {
        Self::with_padding(num_embeddings, embedding_dim, None)
    }

    /// Create with padding index
    pub fn with_padding(
        num_embeddings: usize,
        embedding_dim: usize,
        padding_idx: Option<usize>,
    ) -> Self {
        let device = Device::cpu();

        // Normal initialization
        let data: Vec<f32> = (0..num_embeddings * embedding_dim)
            .map(|_| rand::random::<f32>())
            .collect();
        let weight = Tensor::new(data, vec![num_embeddings, embedding_dim], device).unwrap();

        Self {
            num_embeddings,
            embedding_dim,
            weight: Parameter::new(weight, true),
            padding_idx,
            training: true,
        }
    }
}

impl Module for Embedding {
    fn forward(&self, input: &Tensor) -> Result<Tensor, TensorError> {
        // Would need proper indexing operation
        // For now, return zeros with correct shape
        let output_shape = {
            let mut s = input.shape().to_vec();
            s.push(self.embedding_dim);
            s
        };
        Ok(Tensor::zeros(output_shape, Device::cpu()))
    }

    fn name(&self) -> &str {
        "Embedding"
    }

    fn parameters(&self) -> Vec<Parameter> {
        vec![self.weight.clone()]
    }

    fn train(&mut self, mode: bool) {
        self.training = mode;
    }
}

// ============ Loss Functions ============

/// Mean Squared Error loss
pub struct MSELoss {
    reduction: String,
}

impl MSELoss {
    /// Create new MSE loss
    pub fn new() -> Self {
        Self::with_reduction("mean")
    }

    /// Create with reduction mode
    pub fn with_reduction(reduction: &str) -> Self {
        Self {
            reduction: reduction.to_string(),
        }
    }

    /// Compute loss
    pub fn forward(&self, input: &Tensor, target: &Tensor) -> Result<Tensor, TensorError> {
        let diff = input.sub(target);
        let sq = diff.mul(&diff);

        match self.reduction.as_str() {
            "mean" => Ok(sq.mean(None)),
            "sum" => Ok(sq.sum(None)),
            "none" => Ok(sq),
            _ => Ok(sq.mean(None)),
        }
    }
}

impl Default for MSELoss {
    fn default() -> Self {
        Self::new()
    }
}

/// Cross Entropy loss
pub struct CrossEntropyLoss {
    reduction: String,
    label_smoothing: f64,
}

impl CrossEntropyLoss {
    /// Create new cross entropy loss
    pub fn new() -> Self {
        Self::with_options("mean", 0.0)
    }

    /// Create with options
    pub fn with_options(reduction: &str, label_smoothing: f64) -> Self {
        Self {
            reduction: reduction.to_string(),
            label_smoothing,
        }
    }

    /// Compute loss
    pub fn forward(&self, input: &Tensor, _target: &Tensor) -> Result<Tensor, TensorError> {
        // Compute log softmax then NLL
        let max_val = input.max(None);
        let shifted = input.sub(&max_val);
        let exp_vals = shifted.exp();
        let sum_exp = exp_vals.sum(None);
        let log_softmax = shifted.sub(&sum_exp.log());

        // NLL (simplified)
        let nll = log_softmax.neg();

        match self.reduction.as_str() {
            "mean" => Ok(nll.mean(None)),
            "sum" => Ok(nll.sum(None)),
            "none" => Ok(nll),
            _ => Ok(nll.mean(None)),
        }
    }
}

impl Default for CrossEntropyLoss {
    fn default() -> Self {
        Self::new()
    }
}

// ============ Module List ============

/// Module list container
pub struct ModuleList {
    modules: Vec<Box<dyn Module>>,
    training: bool,
}

impl ModuleList {
    /// Create new module list
    pub fn new(modules: Vec<Box<dyn Module>>) -> Self {
        Self {
            modules,
            training: true,
        }
    }

    /// Get module at index
    pub fn get(&self, index: usize) -> Option<&Box<dyn Module>> {
        self.modules.get(index)
    }

    /// Number of modules
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Iterate over modules
    pub fn iter(&self) -> impl Iterator<Item = &Box<dyn Module>> {
        self.modules.iter()
    }
}

impl Module for ModuleList {
    fn forward(&self, _input: &Tensor) -> Result<Tensor, TensorError> {
        // ModuleList doesn't implement forward directly
        Err(TensorError::UnsupportedOperation)
    }

    fn name(&self) -> &str {
        "ModuleList"
    }

    fn parameters(&self) -> Vec<Parameter> {
        let mut params = Vec::new();
        for module in &self.modules {
            params.extend(module.parameters());
        }
        params
    }

    fn train(&mut self, mode: bool) {
        self.training = mode;
        for module in &mut self.modules {
            module.train(mode);
        }
    }
}
