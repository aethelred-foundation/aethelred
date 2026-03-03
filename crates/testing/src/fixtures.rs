//! Aethelred SDK Test Fixtures
//!
//! Provides reusable test fixtures for AI/ML testing including
//! data generators, model fixtures, and environment setup utilities.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::fs;

// ============ Fixture Registry ============

/// Global fixture registry
static FIXTURE_REGISTRY: std::sync::OnceLock<RwLock<FixtureRegistry>> = std::sync::OnceLock::new();

fn get_registry() -> &'static RwLock<FixtureRegistry> {
    FIXTURE_REGISTRY.get_or_init(|| RwLock::new(FixtureRegistry::new()))
}

/// Registry for named fixtures
pub struct FixtureRegistry {
    fixtures: HashMap<String, Arc<dyn Fixture>>,
}

impl FixtureRegistry {
    pub fn new() -> Self {
        FixtureRegistry {
            fixtures: HashMap::new(),
        }
    }

    pub fn register<F: Fixture + 'static>(&mut self, name: &str, fixture: F) {
        self.fixtures.insert(name.to_string(), Arc::new(fixture));
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Fixture>> {
        self.fixtures.get(name).cloned()
    }
}

/// Trait for test fixtures
pub trait Fixture: Send + Sync {
    fn setup(&self) -> Result<(), Box<dyn std::error::Error>>;
    fn teardown(&self) -> Result<(), Box<dyn std::error::Error>>;
    fn name(&self) -> &str;
}

/// Register a fixture globally
pub fn register_fixture<F: Fixture + 'static>(name: &str, fixture: F) {
    let mut registry = get_registry().write().unwrap();
    registry.register(name, fixture);
}

/// Get a fixture by name
pub fn get_fixture(name: &str) -> Option<Arc<dyn Fixture>> {
    let registry = get_registry().read().unwrap();
    registry.get(name)
}

// ============ Temporary Directory Fixture ============

/// Fixture that creates a temporary directory
pub struct TempDirFixture {
    name: String,
    path: Mutex<Option<tempfile::TempDir>>,
}

impl TempDirFixture {
    pub fn new(name: impl Into<String>) -> Self {
        TempDirFixture {
            name: name.into(),
            path: Mutex::new(None),
        }
    }

    pub fn path(&self) -> Option<PathBuf> {
        self.path.lock().unwrap().as_ref().map(|d| d.path().to_path_buf())
    }
}

impl Fixture for TempDirFixture {
    fn setup(&self) -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = tempfile::tempdir()?;
        *self.path.lock().unwrap() = Some(temp_dir);
        Ok(())
    }

    fn teardown(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut path = self.path.lock().unwrap();
        *path = None; // Drop the tempdir, which cleans up
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ============ Model Fixture ============

/// Configuration for model fixtures
#[derive(Debug, Clone)]
pub struct ModelConfig {
    pub name: String,
    pub input_shape: Vec<usize>,
    pub output_shape: Vec<usize>,
    pub dtype: DataType,
    pub device: Device,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DataType {
    Float32,
    Float16,
    BFloat16,
    Int8,
    Int32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Device {
    CPU,
    CUDA(usize),
    TEE,
}

/// Fixture for model testing
pub struct ModelFixture {
    name: String,
    config: ModelConfig,
    weights: Mutex<Option<Vec<f32>>>,
}

impl ModelFixture {
    pub fn new(config: ModelConfig) -> Self {
        ModelFixture {
            name: config.name.clone(),
            config,
            weights: Mutex::new(None),
        }
    }

    pub fn weights(&self) -> Option<Vec<f32>> {
        self.weights.lock().unwrap().clone()
    }

    pub fn config(&self) -> &ModelConfig {
        &self.config
    }
}

impl Fixture for ModelFixture {
    fn setup(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Generate random weights
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let weight_count: usize = self.config.input_shape.iter().product::<usize>()
            * self.config.output_shape.iter().product::<usize>();

        let weights: Vec<f32> = (0..weight_count).map(|_| rng.gen::<f32>() * 0.01).collect();
        *self.weights.lock().unwrap() = Some(weights);

        Ok(())
    }

    fn teardown(&self) -> Result<(), Box<dyn std::error::Error>> {
        *self.weights.lock().unwrap() = None;
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ============ Data Generators ============

/// Generator for test data
pub struct DataGenerator {
    seed: u64,
}

impl DataGenerator {
    pub fn new(seed: u64) -> Self {
        DataGenerator { seed }
    }

    pub fn seeded() -> Self {
        DataGenerator { seed: 42 }
    }

    /// Generate random tensor data
    pub fn random_tensor(&self, shape: &[usize]) -> Vec<f32> {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.seed);
        let size: usize = shape.iter().product();
        (0..size).map(|_| rng.gen::<f32>()).collect()
    }

    /// Generate tensor with normal distribution (Box-Muller transform)
    pub fn normal_tensor(&self, shape: &[usize], mean: f32, std: f32) -> Vec<f32> {
        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(self.seed);
        let size: usize = shape.iter().product();
        let mut result = Vec::with_capacity(size);
        while result.len() < size {
            let u1: f32 = rng.gen::<f32>().max(f32::EPSILON);
            let u2: f32 = rng.gen::<f32>();
            let z0 = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f32::consts::PI * u2).cos();
            result.push(mean + std * z0);
            if result.len() < size {
                let z1 = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f32::consts::PI * u2).sin();
                result.push(mean + std * z1);
            }
        }
        result.truncate(size);
        result
    }

    /// Generate tensor with uniform distribution
    pub fn uniform_tensor(&self, shape: &[usize], min: f32, max: f32) -> Vec<f32> {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.seed);
        let size: usize = shape.iter().product();
        (0..size).map(|_| rng.gen_range(min..max)).collect()
    }

    /// Generate one-hot encoded data
    pub fn one_hot(&self, indices: &[usize], num_classes: usize) -> Vec<Vec<f32>> {
        indices.iter().map(|&idx| {
            let mut vec = vec![0.0; num_classes];
            if idx < num_classes {
                vec[idx] = 1.0;
            }
            vec
        }).collect()
    }

    /// Generate sequential data for RNN testing
    pub fn sequential_data(&self, batch_size: usize, seq_length: usize, features: usize) -> Vec<f32> {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.seed);
        let size = batch_size * seq_length * features;
        (0..size).map(|_| rng.gen::<f32>()).collect()
    }

    /// Generate image-like data (NCHW format)
    pub fn image_data(&self, batch_size: usize, channels: usize, height: usize, width: usize) -> Vec<f32> {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.seed);
        let size = batch_size * channels * height * width;
        (0..size).map(|_| rng.gen_range(0.0..1.0)).collect()
    }

    /// Generate attention mask
    pub fn attention_mask(&self, batch_size: usize, seq_length: usize) -> Vec<f32> {
        vec![1.0; batch_size * seq_length]
    }

    /// Generate causal attention mask
    pub fn causal_mask(&self, seq_length: usize) -> Vec<f32> {
        let mut mask = vec![0.0; seq_length * seq_length];
        for i in 0..seq_length {
            for j in 0..=i {
                mask[i * seq_length + j] = 1.0;
            }
        }
        mask
    }

    /// Generate sparse data
    pub fn sparse_tensor(&self, shape: &[usize], sparsity: f32) -> (Vec<usize>, Vec<f32>) {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(self.seed);
        let size: usize = shape.iter().product();

        let mut indices = Vec::new();
        let mut values = Vec::new();

        for i in 0..size {
            if rng.gen::<f32>() > sparsity {
                indices.push(i);
                values.push(rng.gen::<f32>());
            }
        }

        (indices, values)
    }
}

// ============ Dataset Fixtures ============

/// Synthetic dataset for classification testing
pub struct ClassificationDataset {
    pub features: Vec<Vec<f32>>,
    pub labels: Vec<usize>,
    pub num_classes: usize,
}

impl ClassificationDataset {
    /// Generate linearly separable dataset
    pub fn linear(num_samples: usize, num_features: usize, num_classes: usize, seed: u64) -> Self {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let samples_per_class = num_samples / num_classes;
        let mut features = Vec::new();
        let mut labels = Vec::new();

        for class in 0..num_classes {
            let center: Vec<f32> = (0..num_features)
                .map(|_| rng.gen_range(-1.0..1.0))
                .collect();

            for _ in 0..samples_per_class {
                let sample: Vec<f32> = center.iter()
                    .map(|&c| c + rng.gen_range(-0.3..0.3))
                    .collect();
                features.push(sample);
                labels.push(class);
            }
        }

        ClassificationDataset {
            features,
            labels,
            num_classes,
        }
    }

    /// Generate XOR-like non-linear dataset
    pub fn xor(num_samples: usize, seed: u64) -> Self {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let samples_per_quadrant = num_samples / 4;
        let mut features = Vec::new();
        let mut labels = Vec::new();

        let quadrants = [(0.5, 0.5, 0), (-0.5, 0.5, 1), (-0.5, -0.5, 0), (0.5, -0.5, 1)];

        for (cx, cy, label) in quadrants {
            for _ in 0..samples_per_quadrant {
                features.push(vec![
                    cx + rng.gen_range(-0.3..0.3),
                    cy + rng.gen_range(-0.3..0.3),
                ]);
                labels.push(label);
            }
        }

        ClassificationDataset {
            features,
            labels,
            num_classes: 2,
        }
    }

    /// Split dataset into train/test
    pub fn split(&self, train_ratio: f32, seed: u64) -> (ClassificationDataset, ClassificationDataset) {
        use rand::{seq::SliceRandom, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let mut indices: Vec<usize> = (0..self.features.len()).collect();
        indices.shuffle(&mut rng);

        let split_idx = (self.features.len() as f32 * train_ratio) as usize;

        let (train_idx, test_idx) = indices.split_at(split_idx);

        let train = ClassificationDataset {
            features: train_idx.iter().map(|&i| self.features[i].clone()).collect(),
            labels: train_idx.iter().map(|&i| self.labels[i]).collect(),
            num_classes: self.num_classes,
        };

        let test = ClassificationDataset {
            features: test_idx.iter().map(|&i| self.features[i].clone()).collect(),
            labels: test_idx.iter().map(|&i| self.labels[i]).collect(),
            num_classes: self.num_classes,
        };

        (train, test)
    }
}

/// Synthetic dataset for regression testing
pub struct RegressionDataset {
    pub features: Vec<Vec<f32>>,
    pub targets: Vec<f32>,
}

impl RegressionDataset {
    /// Generate linear regression dataset
    pub fn linear(num_samples: usize, num_features: usize, seed: u64) -> Self {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        // Random coefficients
        let coefficients: Vec<f32> = (0..num_features).map(|_| rng.gen_range(-2.0..2.0)).collect();
        let bias = rng.gen_range(-1.0..1.0);

        let mut features = Vec::new();
        let mut targets = Vec::new();

        for _ in 0..num_samples {
            let x: Vec<f32> = (0..num_features).map(|_| rng.gen_range(-1.0..1.0)).collect();
            let y: f32 = x.iter().zip(coefficients.iter())
                .map(|(xi, ci)| xi * ci)
                .sum::<f32>() + bias + rng.gen_range(-0.1..0.1);

            features.push(x);
            targets.push(y);
        }

        RegressionDataset { features, targets }
    }

    /// Generate polynomial regression dataset
    pub fn polynomial(num_samples: usize, degree: usize, seed: u64) -> Self {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

        let coefficients: Vec<f32> = (0..=degree).map(|_| rng.gen_range(-1.0..1.0)).collect();

        let mut features = Vec::new();
        let mut targets = Vec::new();

        for _ in 0..num_samples {
            let x: f32 = rng.gen_range(-2.0..2.0);
            let y: f32 = coefficients.iter().enumerate()
                .map(|(i, &c)| c * x.powi(i as i32))
                .sum::<f32>() + rng.gen_range(-0.05..0.05);

            features.push(vec![x]);
            targets.push(y);
        }

        RegressionDataset { features, targets }
    }
}

// ============ Environment Fixtures ============

/// Fixture for environment variables
pub struct EnvFixture {
    name: String,
    vars: HashMap<String, String>,
    original_values: Mutex<HashMap<String, Option<String>>>,
}

impl EnvFixture {
    pub fn new(name: impl Into<String>) -> Self {
        EnvFixture {
            name: name.into(),
            vars: HashMap::new(),
            original_values: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.vars.insert(key.into(), value.into());
        self
    }
}

impl Fixture for EnvFixture {
    fn setup(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut originals = self.original_values.lock().unwrap();

        for (key, value) in &self.vars {
            originals.insert(key.clone(), std::env::var(key).ok());
            std::env::set_var(key, value);
        }

        Ok(())
    }

    fn teardown(&self) -> Result<(), Box<dyn std::error::Error>> {
        let originals = self.original_values.lock().unwrap();

        for (key, original) in originals.iter() {
            match original {
                Some(val) => std::env::set_var(key, val),
                None => std::env::remove_var(key),
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ============ HTTP Mock Fixture ============

/// Fixture for mocking HTTP responses
pub struct HttpMockFixture {
    name: String,
    mocks: Vec<HttpMock>,
}

#[derive(Clone)]
pub struct HttpMock {
    pub method: String,
    pub path: String,
    pub status: u16,
    pub response_body: String,
    pub response_headers: HashMap<String, String>,
}

impl HttpMockFixture {
    pub fn new(name: impl Into<String>) -> Self {
        HttpMockFixture {
            name: name.into(),
            mocks: Vec::new(),
        }
    }

    pub fn mock(mut self, method: &str, path: &str, status: u16, body: &str) -> Self {
        self.mocks.push(HttpMock {
            method: method.to_string(),
            path: path.to_string(),
            status,
            response_body: body.to_string(),
            response_headers: HashMap::new(),
        });
        self
    }

    pub fn get_mock(&self, method: &str, path: &str) -> Option<&HttpMock> {
        self.mocks.iter().find(|m| m.method == method && m.path == path)
    }
}

impl Fixture for HttpMockFixture {
    fn setup(&self) -> Result<(), Box<dyn std::error::Error>> {
        // In a real implementation, this would start a mock server
        Ok(())
    }

    fn teardown(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Stop mock server
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ============ Fixture Scope ============

/// Manages fixture lifecycle within a scope
pub struct FixtureScope {
    fixtures: Vec<Arc<dyn Fixture>>,
}

impl FixtureScope {
    pub fn new() -> Self {
        FixtureScope { fixtures: Vec::new() }
    }

    pub fn add<F: Fixture + 'static>(&mut self, fixture: F) -> &mut Self {
        self.fixtures.push(Arc::new(fixture));
        self
    }

    pub fn setup_all(&self) -> Result<(), Box<dyn std::error::Error>> {
        for fixture in &self.fixtures {
            fixture.setup()?;
        }
        Ok(())
    }

    pub fn teardown_all(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Teardown in reverse order
        for fixture in self.fixtures.iter().rev() {
            fixture.teardown()?;
        }
        Ok(())
    }

    /// Run a function with fixtures
    pub fn run<F, R>(&self, f: F) -> Result<R, Box<dyn std::error::Error>>
    where
        F: FnOnce() -> R,
    {
        self.setup_all()?;
        let result = f();
        self.teardown_all()?;
        Ok(result)
    }
}

impl Default for FixtureScope {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FixtureScope {
    fn drop(&mut self) {
        // Best effort teardown on drop
        let _ = self.teardown_all();
    }
}

// ============ Fixture Builder ============

/// Builder for creating complex fixtures
pub struct FixtureBuilder {
    temp_dirs: Vec<TempDirFixture>,
    env_vars: HashMap<String, String>,
    files: Vec<(PathBuf, String)>,
}

impl FixtureBuilder {
    pub fn new() -> Self {
        FixtureBuilder {
            temp_dirs: Vec::new(),
            env_vars: HashMap::new(),
            files: Vec::new(),
        }
    }

    pub fn with_temp_dir(mut self, name: &str) -> Self {
        self.temp_dirs.push(TempDirFixture::new(name));
        self
    }

    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env_vars.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_file(mut self, path: impl AsRef<Path>, content: &str) -> Self {
        self.files.push((path.as_ref().to_path_buf(), content.to_string()));
        self
    }

    pub fn build(self) -> FixtureScope {
        let mut scope = FixtureScope::new();

        for temp_dir in self.temp_dirs {
            scope.add(temp_dir);
        }

        if !self.env_vars.is_empty() {
            let mut env = EnvFixture::new("env");
            for (k, v) in self.env_vars {
                env = env.with_var(k, v);
            }
            scope.add(env);
        }

        scope
    }
}

impl Default for FixtureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_generator() {
        let gen = DataGenerator::seeded();
        let data = gen.random_tensor(&[2, 3]);
        assert_eq!(data.len(), 6);
    }

    #[test]
    fn test_classification_dataset() {
        let dataset = ClassificationDataset::linear(100, 4, 2, 42);
        assert_eq!(dataset.features.len(), 100);
        assert_eq!(dataset.labels.len(), 100);
    }

    #[test]
    fn test_fixture_scope() {
        let scope = FixtureBuilder::new()
            .with_temp_dir("test")
            .with_env("TEST_VAR", "test_value")
            .build();

        let result = scope.run(|| {
            42
        });

        assert_eq!(result.unwrap(), 42);
    }
}
