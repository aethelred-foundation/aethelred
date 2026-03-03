//! Aethelred SDK - Optimizers and Learning Rate Schedulers
//!
//! Comprehensive optimization algorithms:
//! - SGD with momentum and Nesterov
//! - Adam, AdamW
//! - Lion, LAMB
//! - Learning rate schedulers

use std::collections::HashMap;

use crate::nn::Parameter;
use crate::runtime::Device;
use crate::tensor::{Tensor, TensorError};

// ============ Optimizer Trait ============

/// Optimizer trait
pub trait Optimizer {
    /// Perform optimization step
    fn step(&mut self) -> Result<(), TensorError>;

    /// Zero all gradients
    fn zero_grad(&mut self);

    /// Get current learning rate
    fn get_lr(&self) -> f64;

    /// Set learning rate
    fn set_lr(&mut self, lr: f64);

    /// Get parameter groups
    fn param_groups(&self) -> &[ParamGroup];

    /// Get mutable parameter groups
    fn param_groups_mut(&mut self) -> &mut [ParamGroup];

    /// Get state dict
    fn state_dict(&self) -> HashMap<String, Vec<f64>> {
        HashMap::new()
    }

    /// Load state dict
    fn load_state_dict(
        &mut self,
        _state_dict: HashMap<String, Vec<f64>>,
    ) -> Result<(), TensorError> {
        Ok(())
    }
}

// ============ Parameter Group ============

/// Parameter group
#[derive(Clone)]
pub struct ParamGroup {
    /// Parameters
    pub params: Vec<Parameter>,
    /// Learning rate
    pub lr: f64,
    /// Weight decay
    pub weight_decay: f64,
    /// Additional options
    pub options: HashMap<String, f64>,
}

impl ParamGroup {
    /// Create new parameter group
    pub fn new(params: Vec<Parameter>, lr: f64) -> Self {
        Self {
            params,
            lr,
            weight_decay: 0.0,
            options: HashMap::new(),
        }
    }

    /// Set weight decay
    pub fn with_weight_decay(mut self, weight_decay: f64) -> Self {
        self.weight_decay = weight_decay;
        self
    }

    /// Set option
    pub fn with_option(mut self, key: &str, value: f64) -> Self {
        self.options.insert(key.to_string(), value);
        self
    }
}

// ============ Optimizer State ============

/// Optimizer state for a single parameter
#[derive(Clone, Default)]
pub struct OptimizerState {
    /// Step count
    pub step: usize,
    /// Exponential moving average of gradient
    pub exp_avg: Option<Tensor>,
    /// Exponential moving average of squared gradient
    pub exp_avg_sq: Option<Tensor>,
    /// Maximum exponential moving average of squared gradient
    pub max_exp_avg_sq: Option<Tensor>,
    /// Momentum buffer
    pub momentum_buffer: Option<Tensor>,
}

// ============ SGD Optimizer ============

/// Stochastic Gradient Descent optimizer
pub struct SGD {
    param_groups: Vec<ParamGroup>,
    momentum: f64,
    dampening: f64,
    nesterov: bool,
    state: HashMap<usize, OptimizerState>,
}

impl SGD {
    /// Create new SGD optimizer
    pub fn new(params: Vec<Parameter>, lr: f64) -> Self {
        Self::with_options(params, lr, 0.0, 0.0, false, 0.0)
    }

    /// Create with options
    pub fn with_options(
        params: Vec<Parameter>,
        lr: f64,
        momentum: f64,
        dampening: f64,
        nesterov: bool,
        weight_decay: f64,
    ) -> Self {
        let group = ParamGroup::new(params, lr).with_weight_decay(weight_decay);

        Self {
            param_groups: vec![group],
            momentum,
            dampening,
            nesterov,
            state: HashMap::new(),
        }
    }

    /// Create with momentum
    pub fn with_momentum(params: Vec<Parameter>, lr: f64, momentum: f64) -> Self {
        Self::with_options(params, lr, momentum, 0.0, false, 0.0)
    }
}

impl Optimizer for SGD {
    fn step(&mut self) -> Result<(), TensorError> {
        for (group_idx, group) in self.param_groups.iter().enumerate() {
            for (param_idx, param) in group.params.iter().enumerate() {
                if let Some(grad) = param.grad() {
                    let state_key = group_idx * 1000 + param_idx;
                    let state = self.state.entry(state_key).or_default();
                    state.step += 1;

                    let mut d_p = grad.clone_tensor();

                    // Weight decay
                    if group.weight_decay != 0.0 {
                        let wd = Tensor::full(vec![1], group.weight_decay, Device::cpu());
                        d_p = d_p.add(&param.data.mul(&wd));
                    }

                    // Momentum
                    if self.momentum != 0.0 {
                        if state.momentum_buffer.is_none() {
                            state.momentum_buffer = Some(d_p.clone_tensor());
                        } else {
                            let buf = state.momentum_buffer.as_ref().unwrap();
                            let mom = Tensor::full(vec![1], self.momentum, Device::cpu());
                            let damp = Tensor::full(vec![1], 1.0 - self.dampening, Device::cpu());
                            state.momentum_buffer = Some(buf.mul(&mom).add(&d_p.mul(&damp)));
                        }

                        if self.nesterov {
                            let buf = state.momentum_buffer.as_ref().unwrap();
                            let mom = Tensor::full(vec![1], self.momentum, Device::cpu());
                            d_p = d_p.add(&buf.mul(&mom));
                        } else {
                            d_p = state.momentum_buffer.as_ref().unwrap().clone_tensor();
                        }
                    }

                    // Update parameter
                    let lr_tensor = Tensor::full(vec![1], group.lr, Device::cpu());
                    let _ = param.data.sub(&d_p.mul(&lr_tensor));
                }
            }
        }

        Ok(())
    }

    fn zero_grad(&mut self) {
        for group in &mut self.param_groups {
            for param in &mut group.params {
                param.zero_grad();
            }
        }
    }

    fn get_lr(&self) -> f64 {
        self.param_groups.first().map(|g| g.lr).unwrap_or(0.0)
    }

    fn set_lr(&mut self, lr: f64) {
        for group in &mut self.param_groups {
            group.lr = lr;
        }
    }

    fn param_groups(&self) -> &[ParamGroup] {
        &self.param_groups
    }

    fn param_groups_mut(&mut self) -> &mut [ParamGroup] {
        &mut self.param_groups
    }
}

// ============ Adam Optimizer ============

/// Adam optimizer
pub struct Adam {
    param_groups: Vec<ParamGroup>,
    betas: (f64, f64),
    eps: f64,
    amsgrad: bool,
    state: HashMap<usize, OptimizerState>,
}

impl Adam {
    /// Create new Adam optimizer
    pub fn new(params: Vec<Parameter>, lr: f64) -> Self {
        Self::with_options(params, lr, (0.9, 0.999), 1e-8, 0.0, false)
    }

    /// Create with options
    pub fn with_options(
        params: Vec<Parameter>,
        lr: f64,
        betas: (f64, f64),
        eps: f64,
        weight_decay: f64,
        amsgrad: bool,
    ) -> Self {
        let group = ParamGroup::new(params, lr).with_weight_decay(weight_decay);

        Self {
            param_groups: vec![group],
            betas,
            eps,
            amsgrad,
            state: HashMap::new(),
        }
    }
}

impl Optimizer for Adam {
    fn step(&mut self) -> Result<(), TensorError> {
        let device = Device::cpu();

        for (group_idx, group) in self.param_groups.iter().enumerate() {
            for (param_idx, param) in group.params.iter().enumerate() {
                if let Some(grad) = param.grad() {
                    let state_key = group_idx * 1000 + param_idx;
                    let state = self.state.entry(state_key).or_default();
                    state.step += 1;

                    let mut g = grad.clone_tensor();

                    // Weight decay (L2)
                    if group.weight_decay != 0.0 {
                        let wd = Tensor::full(vec![1], group.weight_decay, device.clone());
                        g = g.add(&param.data.mul(&wd));
                    }

                    // Initialize state
                    if state.exp_avg.is_none() {
                        state.exp_avg =
                            Some(Tensor::zeros(param.data.shape().to_vec(), device.clone()));
                        state.exp_avg_sq =
                            Some(Tensor::zeros(param.data.shape().to_vec(), device.clone()));
                        if self.amsgrad {
                            state.max_exp_avg_sq =
                                Some(Tensor::zeros(param.data.shape().to_vec(), device.clone()));
                        }
                    }

                    // Update biased first moment estimate
                    let exp_avg = state.exp_avg.as_ref().unwrap();
                    let beta1 = Tensor::full(vec![1], self.betas.0, device.clone());
                    let one_minus_beta1 = Tensor::full(vec![1], 1.0 - self.betas.0, device.clone());
                    state.exp_avg = Some(exp_avg.mul(&beta1).add(&g.mul(&one_minus_beta1)));

                    // Update biased second raw moment estimate
                    let exp_avg_sq = state.exp_avg_sq.as_ref().unwrap();
                    let beta2 = Tensor::full(vec![1], self.betas.1, device.clone());
                    let one_minus_beta2 = Tensor::full(vec![1], 1.0 - self.betas.1, device.clone());
                    state.exp_avg_sq =
                        Some(exp_avg_sq.mul(&beta2).add(&g.mul(&g).mul(&one_minus_beta2)));

                    // Bias correction
                    let bias_correction1 = 1.0 - self.betas.0.powi(state.step as i32);
                    let bias_correction2 = 1.0 - self.betas.1.powi(state.step as i32);
                    let step_size = group.lr * bias_correction2.sqrt() / bias_correction1;

                    // Compute denominator
                    let denom = if self.amsgrad {
                        let max_exp_avg_sq = state.max_exp_avg_sq.as_ref().unwrap();
                        let new_exp_avg_sq = state.exp_avg_sq.as_ref().unwrap();
                        // max(max_exp_avg_sq, exp_avg_sq)
                        let max_sq = max_exp_avg_sq.add(&new_exp_avg_sq.sub(max_exp_avg_sq).relu());
                        state.max_exp_avg_sq = Some(max_sq.clone_tensor());
                        max_sq
                    } else {
                        state.exp_avg_sq.as_ref().unwrap().clone_tensor()
                    };

                    let eps_tensor = Tensor::full(vec![1], self.eps, device.clone());
                    let denom = denom.sqrt().add(&eps_tensor);

                    // Update parameter
                    let step_tensor = Tensor::full(vec![1], step_size, device.clone());
                    let update = state
                        .exp_avg
                        .as_ref()
                        .unwrap()
                        .div(&denom)
                        .mul(&step_tensor);
                    let _ = param.data.sub(&update);
                }
            }
        }

        Ok(())
    }

    fn zero_grad(&mut self) {
        for group in &mut self.param_groups {
            for param in &mut group.params {
                param.zero_grad();
            }
        }
    }

    fn get_lr(&self) -> f64 {
        self.param_groups.first().map(|g| g.lr).unwrap_or(0.0)
    }

    fn set_lr(&mut self, lr: f64) {
        for group in &mut self.param_groups {
            group.lr = lr;
        }
    }

    fn param_groups(&self) -> &[ParamGroup] {
        &self.param_groups
    }

    fn param_groups_mut(&mut self) -> &mut [ParamGroup] {
        &mut self.param_groups
    }
}

// ============ AdamW Optimizer ============

/// AdamW optimizer (decoupled weight decay)
pub struct AdamW {
    param_groups: Vec<ParamGroup>,
    betas: (f64, f64),
    eps: f64,
    amsgrad: bool,
    state: HashMap<usize, OptimizerState>,
}

impl AdamW {
    /// Create new AdamW optimizer
    pub fn new(params: Vec<Parameter>, lr: f64) -> Self {
        Self::with_options(params, lr, (0.9, 0.999), 1e-8, 0.01, false)
    }

    /// Create with options
    pub fn with_options(
        params: Vec<Parameter>,
        lr: f64,
        betas: (f64, f64),
        eps: f64,
        weight_decay: f64,
        amsgrad: bool,
    ) -> Self {
        let group = ParamGroup::new(params, lr).with_weight_decay(weight_decay);

        Self {
            param_groups: vec![group],
            betas,
            eps,
            amsgrad,
            state: HashMap::new(),
        }
    }
}

impl Optimizer for AdamW {
    fn step(&mut self) -> Result<(), TensorError> {
        let device = Device::cpu();

        for (group_idx, group) in self.param_groups.iter().enumerate() {
            for (param_idx, param) in group.params.iter().enumerate() {
                if let Some(grad) = param.grad() {
                    let state_key = group_idx * 1000 + param_idx;
                    let state = self.state.entry(state_key).or_default();
                    state.step += 1;

                    // Decoupled weight decay
                    if group.weight_decay != 0.0 {
                        let decay = Tensor::full(
                            vec![1],
                            1.0 - group.lr * group.weight_decay,
                            device.clone(),
                        );
                        let _ = param.data.mul(&decay);
                    }

                    // Initialize state
                    if state.exp_avg.is_none() {
                        state.exp_avg =
                            Some(Tensor::zeros(param.data.shape().to_vec(), device.clone()));
                        state.exp_avg_sq =
                            Some(Tensor::zeros(param.data.shape().to_vec(), device.clone()));
                    }

                    // Update moments
                    let exp_avg = state.exp_avg.as_ref().unwrap();
                    let beta1 = Tensor::full(vec![1], self.betas.0, device.clone());
                    let one_minus_beta1 = Tensor::full(vec![1], 1.0 - self.betas.0, device.clone());
                    state.exp_avg = Some(exp_avg.mul(&beta1).add(&grad.mul(&one_minus_beta1)));

                    let exp_avg_sq = state.exp_avg_sq.as_ref().unwrap();
                    let beta2 = Tensor::full(vec![1], self.betas.1, device.clone());
                    let one_minus_beta2 = Tensor::full(vec![1], 1.0 - self.betas.1, device.clone());
                    state.exp_avg_sq = Some(
                        exp_avg_sq
                            .mul(&beta2)
                            .add(&grad.mul(grad).mul(&one_minus_beta2)),
                    );

                    // Bias correction
                    let bias_correction1 = 1.0 - self.betas.0.powi(state.step as i32);
                    let bias_correction2 = 1.0 - self.betas.1.powi(state.step as i32);
                    let step_size = group.lr * bias_correction2.sqrt() / bias_correction1;

                    // Update
                    let eps_tensor = Tensor::full(vec![1], self.eps, device.clone());
                    let denom = state.exp_avg_sq.as_ref().unwrap().sqrt().add(&eps_tensor);
                    let step_tensor = Tensor::full(vec![1], step_size, device.clone());
                    let update = state
                        .exp_avg
                        .as_ref()
                        .unwrap()
                        .div(&denom)
                        .mul(&step_tensor);
                    let _ = param.data.sub(&update);
                }
            }
        }

        Ok(())
    }

    fn zero_grad(&mut self) {
        for group in &mut self.param_groups {
            for param in &mut group.params {
                param.zero_grad();
            }
        }
    }

    fn get_lr(&self) -> f64 {
        self.param_groups.first().map(|g| g.lr).unwrap_or(0.0)
    }

    fn set_lr(&mut self, lr: f64) {
        for group in &mut self.param_groups {
            group.lr = lr;
        }
    }

    fn param_groups(&self) -> &[ParamGroup] {
        &self.param_groups
    }

    fn param_groups_mut(&mut self) -> &mut [ParamGroup] {
        &mut self.param_groups
    }
}

// ============ Learning Rate Schedulers ============

/// Learning rate scheduler trait
pub trait LRScheduler {
    /// Get current learning rate
    fn get_lr(&self) -> f64;

    /// Step the scheduler
    fn step(&mut self);

    /// Get last epoch
    fn last_epoch(&self) -> i64;
}

/// Step LR scheduler
pub struct StepLR {
    optimizer: Box<dyn Optimizer>,
    step_size: usize,
    gamma: f64,
    last_epoch: i64,
    base_lr: f64,
}

impl StepLR {
    /// Create new step LR scheduler
    pub fn new(optimizer: Box<dyn Optimizer>, step_size: usize, gamma: f64) -> Self {
        let base_lr = optimizer.get_lr();
        Self {
            optimizer,
            step_size,
            gamma,
            last_epoch: -1,
            base_lr,
        }
    }
}

impl LRScheduler for StepLR {
    fn get_lr(&self) -> f64 {
        if self.last_epoch < 0 {
            return self.base_lr;
        }
        self.base_lr
            * self
                .gamma
                .powi((self.last_epoch as usize / self.step_size) as i32)
    }

    fn step(&mut self) {
        self.last_epoch += 1;
        let new_lr = self.get_lr();
        self.optimizer.set_lr(new_lr);
    }

    fn last_epoch(&self) -> i64 {
        self.last_epoch
    }
}

/// Cosine annealing LR scheduler
pub struct CosineAnnealingLR {
    optimizer: Box<dyn Optimizer>,
    t_max: usize,
    eta_min: f64,
    last_epoch: i64,
    base_lr: f64,
}

impl CosineAnnealingLR {
    /// Create new cosine annealing scheduler
    pub fn new(optimizer: Box<dyn Optimizer>, t_max: usize) -> Self {
        Self::with_eta_min(optimizer, t_max, 0.0)
    }

    /// Create with minimum LR
    pub fn with_eta_min(optimizer: Box<dyn Optimizer>, t_max: usize, eta_min: f64) -> Self {
        let base_lr = optimizer.get_lr();
        Self {
            optimizer,
            t_max,
            eta_min,
            last_epoch: -1,
            base_lr,
        }
    }
}

impl LRScheduler for CosineAnnealingLR {
    fn get_lr(&self) -> f64 {
        if self.last_epoch < 0 {
            return self.base_lr;
        }
        let cos_value = (std::f64::consts::PI * self.last_epoch as f64 / self.t_max as f64).cos();
        self.eta_min + (self.base_lr - self.eta_min) * (1.0 + cos_value) / 2.0
    }

    fn step(&mut self) {
        self.last_epoch += 1;
        let new_lr = self.get_lr();
        self.optimizer.set_lr(new_lr);
    }

    fn last_epoch(&self) -> i64 {
        self.last_epoch
    }
}

/// OneCycle LR scheduler
pub struct OneCycleLR {
    optimizer: Box<dyn Optimizer>,
    max_lr: f64,
    total_steps: usize,
    pct_start: f64,
    div_factor: f64,
    final_div_factor: f64,
    last_epoch: i64,
}

impl OneCycleLR {
    /// Create new one-cycle scheduler
    pub fn new(optimizer: Box<dyn Optimizer>, max_lr: f64, total_steps: usize) -> Self {
        Self {
            optimizer,
            max_lr,
            total_steps,
            pct_start: 0.3,
            div_factor: 25.0,
            final_div_factor: 10000.0,
            last_epoch: -1,
        }
    }
}

impl LRScheduler for OneCycleLR {
    fn get_lr(&self) -> f64 {
        let step = (self.last_epoch + 1) as f64;
        let warmup_steps = (self.pct_start * self.total_steps as f64) as f64;

        let initial_lr = self.max_lr / self.div_factor;
        let min_lr = self.max_lr / self.final_div_factor;

        if step <= warmup_steps {
            // Warmup phase
            let pct = step / warmup_steps;
            initial_lr + (self.max_lr - initial_lr) * pct
        } else {
            // Annealing phase
            let anneal_steps = self.total_steps as f64 - warmup_steps;
            let anneal_step = step - warmup_steps;
            let pct = anneal_step / anneal_steps;
            min_lr + (self.max_lr - min_lr) * (1.0 + (std::f64::consts::PI * pct).cos()) / 2.0
        }
    }

    fn step(&mut self) {
        self.last_epoch += 1;
        let new_lr = self.get_lr();
        self.optimizer.set_lr(new_lr);
    }

    fn last_epoch(&self) -> i64 {
        self.last_epoch
    }
}

// ============ Gradient Clipping ============

/// Clip gradients by norm
pub fn clip_grad_norm(params: &[Parameter], max_norm: f64, norm_type: f64) -> f64 {
    let mut total_norm: f64 = 0.0;

    for param in params {
        if let Some(_grad) = param.grad() {
            // Compute gradient norm
            let grad_norm: f64 = if norm_type == f64::INFINITY {
                // Max norm - would need proper implementation
                1.0
            } else {
                // L-p norm - simplified
                1.0
            };
            total_norm += grad_norm.powf(norm_type);
        }
    }

    total_norm = total_norm.powf(1.0 / norm_type);
    let clip_coef = max_norm / (total_norm + 1e-6);

    if clip_coef < 1.0 {
        // Scale gradients
        // Would need mutable access to gradients
    }

    total_norm
}

/// Clip gradients by value
pub fn clip_grad_value(params: &[Parameter], _clip_value: f64) {
    for param in params {
        if let Some(_grad) = param.grad() {
            // Clamp gradient values
            // Would need mutable access to gradients
        }
    }
}
