//! Aethelred SDK Property-Based Testing
//!
//! Property-based testing (fuzzing) framework for AI/ML applications.
//! Generates random inputs to verify properties hold for all inputs.

use std::fmt::Debug;
use std::collections::HashMap;
use std::hash::Hash;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

// ============ Property Test Configuration ============

/// Configuration for property tests
#[derive(Debug, Clone)]
pub struct PropertyConfig {
    /// Number of test cases to generate
    pub num_tests: usize,
    /// Random seed for reproducibility
    pub seed: Option<u64>,
    /// Maximum shrink iterations
    pub max_shrink_iters: usize,
    /// Verbose output
    pub verbose: bool,
}

impl Default for PropertyConfig {
    fn default() -> Self {
        PropertyConfig {
            num_tests: 100,
            seed: None,
            max_shrink_iters: 100,
            verbose: false,
        }
    }
}

// ============ Arbitrary Trait ============

/// Trait for generating arbitrary values
pub trait Arbitrary: Clone + Debug {
    fn arbitrary(rng: &mut StdRng) -> Self;
    fn shrink(&self) -> Vec<Self>;
}

// Implementations for primitive types
impl Arbitrary for bool {
    fn arbitrary(rng: &mut StdRng) -> Self {
        rng.gen()
    }

    fn shrink(&self) -> Vec<Self> {
        if *self { vec![false] } else { vec![] }
    }
}

impl Arbitrary for i32 {
    fn arbitrary(rng: &mut StdRng) -> Self {
        rng.gen_range(-1000..1000)
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();
        if *self != 0 {
            shrinks.push(0);
            shrinks.push(self / 2);
            if *self > 0 {
                shrinks.push(self - 1);
            } else {
                shrinks.push(self + 1);
            }
        }
        shrinks
    }
}

impl Arbitrary for i64 {
    fn arbitrary(rng: &mut StdRng) -> Self {
        rng.gen_range(-10000..10000)
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();
        if *self != 0 {
            shrinks.push(0);
            shrinks.push(self / 2);
            if *self > 0 {
                shrinks.push(self - 1);
            } else {
                shrinks.push(self + 1);
            }
        }
        shrinks
    }
}

impl Arbitrary for u32 {
    fn arbitrary(rng: &mut StdRng) -> Self {
        rng.gen_range(0..1000)
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();
        if *self > 0 {
            shrinks.push(0);
            shrinks.push(self / 2);
            shrinks.push(self - 1);
        }
        shrinks
    }
}

impl Arbitrary for u64 {
    fn arbitrary(rng: &mut StdRng) -> Self {
        rng.gen_range(0..10000)
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();
        if *self > 0 {
            shrinks.push(0);
            shrinks.push(self / 2);
            shrinks.push(self - 1);
        }
        shrinks
    }
}

impl Arbitrary for usize {
    fn arbitrary(rng: &mut StdRng) -> Self {
        rng.gen_range(0..100)
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();
        if *self > 0 {
            shrinks.push(0);
            shrinks.push(self / 2);
            shrinks.push(self - 1);
        }
        shrinks
    }
}

impl Arbitrary for f32 {
    fn arbitrary(rng: &mut StdRng) -> Self {
        rng.gen_range(-100.0..100.0)
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();
        if *self != 0.0 {
            shrinks.push(0.0);
            shrinks.push(self / 2.0);
            shrinks.push(self.trunc());
        }
        shrinks
    }
}

impl Arbitrary for f64 {
    fn arbitrary(rng: &mut StdRng) -> Self {
        rng.gen_range(-1000.0..1000.0)
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();
        if *self != 0.0 {
            shrinks.push(0.0);
            shrinks.push(self / 2.0);
            shrinks.push(self.trunc());
        }
        shrinks
    }
}

impl Arbitrary for String {
    fn arbitrary(rng: &mut StdRng) -> Self {
        let len = rng.gen_range(0..20);
        (0..len).map(|_| rng.gen_range('a'..='z')).collect()
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();
        if !self.is_empty() {
            shrinks.push(String::new());
            shrinks.push(self[..self.len()/2].to_string());
            shrinks.push(self[1..].to_string());
            shrinks.push(self[..self.len()-1].to_string());
        }
        shrinks
    }
}

impl<T: Arbitrary> Arbitrary for Vec<T> {
    fn arbitrary(rng: &mut StdRng) -> Self {
        let len = rng.gen_range(0..10);
        (0..len).map(|_| T::arbitrary(rng)).collect()
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();
        if !self.is_empty() {
            shrinks.push(Vec::new());
            shrinks.push(self[..self.len()/2].to_vec());

            // Remove each element
            for i in 0..self.len() {
                let mut v = self.clone();
                v.remove(i);
                shrinks.push(v);
            }

            // Shrink each element
            for (i, elem) in self.iter().enumerate() {
                for shrunk in elem.shrink() {
                    let mut v = self.clone();
                    v[i] = shrunk;
                    shrinks.push(v);
                }
            }
        }
        shrinks
    }
}

impl<T: Arbitrary> Arbitrary for Option<T> {
    fn arbitrary(rng: &mut StdRng) -> Self {
        if rng.gen_bool(0.8) {
            Some(T::arbitrary(rng))
        } else {
            None
        }
    }

    fn shrink(&self) -> Vec<Self> {
        match self {
            Some(v) => {
                let mut shrinks = vec![None];
                shrinks.extend(v.shrink().into_iter().map(Some));
                shrinks
            }
            None => vec![],
        }
    }
}

impl<A: Arbitrary, B: Arbitrary> Arbitrary for (A, B) {
    fn arbitrary(rng: &mut StdRng) -> Self {
        (A::arbitrary(rng), B::arbitrary(rng))
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();

        for a in self.0.shrink() {
            shrinks.push((a, self.1.clone()));
        }

        for b in self.1.shrink() {
            shrinks.push((self.0.clone(), b));
        }

        shrinks
    }
}

impl<A: Arbitrary, B: Arbitrary, C: Arbitrary> Arbitrary for (A, B, C) {
    fn arbitrary(rng: &mut StdRng) -> Self {
        (A::arbitrary(rng), B::arbitrary(rng), C::arbitrary(rng))
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();

        for a in self.0.shrink() {
            shrinks.push((a, self.1.clone(), self.2.clone()));
        }

        for b in self.1.shrink() {
            shrinks.push((self.0.clone(), b, self.2.clone()));
        }

        for c in self.2.shrink() {
            shrinks.push((self.0.clone(), self.1.clone(), c));
        }

        shrinks
    }
}

// ============ Tensor Generators ============

/// Arbitrary tensor shape
#[derive(Debug, Clone)]
pub struct ArbitraryShape {
    pub dims: Vec<usize>,
    pub max_dim: usize,
    pub max_size: usize,
}

impl ArbitraryShape {
    pub fn new(max_dim: usize, max_size: usize) -> Self {
        ArbitraryShape {
            dims: Vec::new(),
            max_dim,
            max_size,
        }
    }
}

impl Arbitrary for ArbitraryShape {
    fn arbitrary(rng: &mut StdRng) -> Self {
        let max_dim = 4;
        let max_size_per_dim = 10;

        let num_dims = rng.gen_range(1..=max_dim);
        let dims: Vec<usize> = (0..num_dims)
            .map(|_| rng.gen_range(1..=max_size_per_dim))
            .collect();

        ArbitraryShape {
            dims,
            max_dim,
            max_size: 1000,
        }
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();

        // Remove dimensions
        if self.dims.len() > 1 {
            shrinks.push(ArbitraryShape {
                dims: self.dims[..self.dims.len()-1].to_vec(),
                max_dim: self.max_dim,
                max_size: self.max_size,
            });
        }

        // Shrink dimension sizes
        for (i, &d) in self.dims.iter().enumerate() {
            if d > 1 {
                let mut new_dims = self.dims.clone();
                new_dims[i] = d / 2;
                shrinks.push(ArbitraryShape {
                    dims: new_dims,
                    max_dim: self.max_dim,
                    max_size: self.max_size,
                });
            }
        }

        shrinks
    }
}

/// Arbitrary tensor data
#[derive(Debug, Clone)]
pub struct ArbitraryTensor {
    pub shape: Vec<usize>,
    pub data: Vec<f32>,
}

impl ArbitraryTensor {
    pub fn with_shape(shape: Vec<usize>, rng: &mut StdRng) -> Self {
        let size: usize = shape.iter().product();
        let data: Vec<f32> = (0..size).map(|_| rng.gen_range(-1.0..1.0)).collect();
        ArbitraryTensor { shape, data }
    }
}

impl Arbitrary for ArbitraryTensor {
    fn arbitrary(rng: &mut StdRng) -> Self {
        let shape = ArbitraryShape::arbitrary(rng);
        let size: usize = shape.dims.iter().product();
        let data: Vec<f32> = (0..size).map(|_| rng.gen_range(-1.0..1.0)).collect();

        ArbitraryTensor {
            shape: shape.dims,
            data,
        }
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();

        // Shrink to zeros
        shrinks.push(ArbitraryTensor {
            shape: self.shape.clone(),
            data: vec![0.0; self.data.len()],
        });

        // Shrink shape
        if self.shape.len() > 1 {
            let new_shape: Vec<usize> = self.shape[..self.shape.len()-1].to_vec();
            let new_size: usize = new_shape.iter().product();
            shrinks.push(ArbitraryTensor {
                shape: new_shape,
                data: self.data[..new_size.min(self.data.len())].to_vec(),
            });
        }

        shrinks
    }
}

/// Arbitrary normalized tensor (values sum to 1)
#[derive(Debug, Clone)]
pub struct ArbitraryProbabilities {
    pub values: Vec<f32>,
}

impl Arbitrary for ArbitraryProbabilities {
    fn arbitrary(rng: &mut StdRng) -> Self {
        let len = rng.gen_range(2..10);
        let mut values: Vec<f32> = (0..len).map(|_| rng.gen_range(0.0..1.0)).collect();
        let sum: f32 = values.iter().sum();
        for v in &mut values {
            *v /= sum;
        }
        ArbitraryProbabilities { values }
    }

    fn shrink(&self) -> Vec<Self> {
        let mut shrinks = Vec::new();

        if self.values.len() > 2 {
            // Reduce to fewer elements
            let mut new_values = self.values[..self.values.len()-1].to_vec();
            let sum: f32 = new_values.iter().sum();
            for v in &mut new_values {
                *v /= sum;
            }
            shrinks.push(ArbitraryProbabilities { values: new_values });
        }

        shrinks
    }
}

// ============ Property Test Runner ============

/// Result of a property test
#[derive(Debug)]
pub struct PropertyResult<T> {
    pub passed: bool,
    pub num_tests: usize,
    pub seed: u64,
    pub failure: Option<PropertyFailure<T>>,
}

/// Details of a property test failure
#[derive(Debug)]
pub struct PropertyFailure<T> {
    pub original_input: T,
    pub shrunk_input: T,
    pub shrink_steps: usize,
    pub error: String,
}

/// Run a property test
pub fn check<T, F>(property: F, config: PropertyConfig) -> PropertyResult<T>
where
    T: Arbitrary,
    F: Fn(&T) -> bool,
{
    let seed = config.seed.unwrap_or_else(|| {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    });

    let mut rng = StdRng::seed_from_u64(seed);

    for i in 0..config.num_tests {
        let input = T::arbitrary(&mut rng);

        if !property(&input) {
            // Shrink the failing input
            let (shrunk, steps) = shrink_input(&input, &property, config.max_shrink_iters);

            return PropertyResult {
                passed: false,
                num_tests: i + 1,
                seed,
                failure: Some(PropertyFailure {
                    original_input: input,
                    shrunk_input: shrunk,
                    shrink_steps: steps,
                    error: "Property failed".to_string(),
                }),
            };
        }
    }

    PropertyResult {
        passed: true,
        num_tests: config.num_tests,
        seed,
        failure: None,
    }
}

/// Run a property test that may return errors
pub fn check_result<T, E, F>(property: F, config: PropertyConfig) -> PropertyResult<T>
where
    T: Arbitrary,
    E: Debug,
    F: Fn(&T) -> Result<(), E>,
{
    let seed = config.seed.unwrap_or_else(|| {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    });

    let mut rng = StdRng::seed_from_u64(seed);

    for i in 0..config.num_tests {
        let input = T::arbitrary(&mut rng);

        if let Err(e) = property(&input) {
            let error_msg = format!("{:?}", e);

            // Shrink using a wrapper property
            let wrapped_property = |x: &T| property(x).is_ok();
            let (shrunk, steps) = shrink_input(&input, &wrapped_property, config.max_shrink_iters);

            return PropertyResult {
                passed: false,
                num_tests: i + 1,
                seed,
                failure: Some(PropertyFailure {
                    original_input: input,
                    shrunk_input: shrunk,
                    shrink_steps: steps,
                    error: error_msg,
                }),
            };
        }
    }

    PropertyResult {
        passed: true,
        num_tests: config.num_tests,
        seed,
        failure: None,
    }
}

/// Shrink a failing input to a minimal example
fn shrink_input<T, F>(input: &T, property: &F, max_iters: usize) -> (T, usize)
where
    T: Arbitrary,
    F: Fn(&T) -> bool,
{
    let mut current = input.clone();
    let mut steps = 0;

    for _ in 0..max_iters {
        let shrinks = current.shrink();
        let mut improved = false;

        for shrunk in shrinks {
            if !property(&shrunk) {
                current = shrunk;
                steps += 1;
                improved = true;
                break;
            }
        }

        if !improved {
            break;
        }
    }

    (current, steps)
}

// ============ Property Combinators ============

/// Combine properties with AND
pub fn all<T>(properties: Vec<Box<dyn Fn(&T) -> bool>>) -> impl Fn(&T) -> bool {
    move |input| properties.iter().all(|p| p(input))
}

/// Combine properties with OR
pub fn any<T>(properties: Vec<Box<dyn Fn(&T) -> bool>>) -> impl Fn(&T) -> bool {
    move |input| properties.iter().any(|p| p(input))
}

/// Implication: if precondition holds, then property must hold
pub fn implies<T, P, Q>(precondition: P, property: Q) -> impl Fn(&T) -> bool
where
    P: Fn(&T) -> bool,
    Q: Fn(&T) -> bool,
{
    move |input| !precondition(input) || property(input)
}

/// Generate values satisfying a predicate
pub fn such_that<T: Arbitrary, F>(predicate: F, max_attempts: usize, rng: &mut StdRng) -> Option<T>
where
    F: Fn(&T) -> bool,
{
    for _ in 0..max_attempts {
        let value = T::arbitrary(rng);
        if predicate(&value) {
            return Some(value);
        }
    }
    None
}

// ============ Common Properties ============

/// Property: function is idempotent (f(f(x)) == f(x))
pub fn idempotent<T, F>(f: F) -> impl Fn(&T) -> bool
where
    T: Clone + PartialEq,
    F: Fn(&T) -> T + Clone,
{
    let f2 = f.clone();
    move |x| f(x) == f2(&f2(x))
}

/// Property: function is involutory (f(f(x)) == x)
pub fn involutory<T, F>(f: F) -> impl Fn(&T) -> bool
where
    T: Clone + PartialEq,
    F: Fn(&T) -> T + Clone,
{
    let f2 = f.clone();
    move |x| *x == f(&f2(x))
}

/// Property: function preserves invariant
pub fn preserves_invariant<T, F, I>(f: F, invariant: I) -> impl Fn(&T) -> bool
where
    T: Clone,
    F: Fn(&T) -> T,
    I: Fn(&T) -> bool + Clone,
{
    let inv2 = invariant.clone();
    move |x| {
        if !invariant(x) {
            true // Precondition failed, property vacuously true
        } else {
            let result = f(x);
            inv2(&result)
        }
    }
}

/// Property: two functions produce equal results
pub fn functions_equal<T, R, F, G>(f: F, g: G) -> impl Fn(&T) -> bool
where
    R: PartialEq,
    F: Fn(&T) -> R,
    G: Fn(&T) -> R,
{
    move |x| f(x) == g(x)
}

/// Property: function is monotonic
pub fn monotonic<T, R, F>(f: F) -> impl Fn(&(T, T)) -> bool
where
    T: PartialOrd,
    R: PartialOrd,
    F: Fn(&T) -> R + Clone,
{
    let f2 = f.clone();
    move |(x, y)| {
        if x <= y {
            f(x) <= f2(y)
        } else {
            true
        }
    }
}

/// Property: function output is bounded
pub fn bounded<T, R, F>(f: F, min: R, max: R) -> impl Fn(&T) -> bool
where
    R: PartialOrd + Clone,
    F: Fn(&T) -> R,
{
    move |x| {
        let result = f(x);
        result >= min && result <= max
    }
}

// ============ Tensor Properties ============

/// Property: tensor operation preserves shape
pub fn preserves_shape<F>(f: F) -> impl Fn(&ArbitraryTensor) -> bool
where
    F: Fn(&ArbitraryTensor) -> ArbitraryTensor,
{
    move |tensor| {
        let result = f(tensor);
        result.shape == tensor.shape
    }
}

/// Property: tensor values are finite (no NaN or Inf)
pub fn all_finite(tensor: &ArbitraryTensor) -> bool {
    tensor.data.iter().all(|v| v.is_finite())
}

/// Property: tensor values are in range
pub fn values_in_range(min: f32, max: f32) -> impl Fn(&ArbitraryTensor) -> bool {
    move |tensor| tensor.data.iter().all(|&v| v >= min && v <= max)
}

/// Property: probabilities are valid (non-negative, sum to 1)
pub fn valid_probabilities(probs: &ArbitraryProbabilities) -> bool {
    let all_non_negative = probs.values.iter().all(|&v| v >= 0.0);
    let sum_to_one = (probs.values.iter().sum::<f32>() - 1.0).abs() < 1e-5;
    all_non_negative && sum_to_one
}

// ============ Macros ============

/// Macro for defining property tests
#[macro_export]
macro_rules! prop_test {
    ($name:ident, $type:ty, $property:expr) => {
        #[test]
        fn $name() {
            let result = $crate::property::check::<$type, _>(
                $property,
                $crate::property::PropertyConfig::default(),
            );

            if !result.passed {
                if let Some(failure) = result.failure {
                    panic!(
                        "Property test failed!\n  Seed: {}\n  Original: {:?}\n  Shrunk: {:?}\n  Error: {}",
                        result.seed,
                        failure.original_input,
                        failure.shrunk_input,
                        failure.error
                    );
                }
            }
        }
    };
}

/// Macro for asserting properties
#[macro_export]
macro_rules! assert_property {
    ($type:ty, $property:expr) => {
        let result = $crate::property::check::<$type, _>(
            $property,
            $crate::property::PropertyConfig::default(),
        );

        assert!(
            result.passed,
            "Property failed after {} tests with seed {}",
            result.num_tests,
            result.seed
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arbitrary_i32() {
        let mut rng = StdRng::seed_from_u64(42);
        let value: i32 = Arbitrary::arbitrary(&mut rng);
        assert!(value >= -1000 && value < 1000);
    }

    #[test]
    fn test_arbitrary_vec() {
        let mut rng = StdRng::seed_from_u64(42);
        let value: Vec<i32> = Arbitrary::arbitrary(&mut rng);
        assert!(value.len() <= 10);
    }

    #[test]
    fn test_property_check() {
        let result = check::<i32, _>(|x| x + 0 == *x, PropertyConfig::default());
        assert!(result.passed);
    }

    #[test]
    fn test_property_failure_shrinking() {
        let result = check::<Vec<i32>, _>(
            |v| v.len() < 5,
            PropertyConfig {
                num_tests: 1000,
                ..Default::default()
            },
        );

        if !result.passed {
            if let Some(failure) = result.failure {
                // Shrunk input should be minimal
                assert!(failure.shrunk_input.len() >= 5);
                assert!(failure.shrunk_input.len() <= failure.original_input.len());
            }
        }
    }

    #[test]
    fn test_tensor_properties() {
        let mut rng = StdRng::seed_from_u64(42);
        let tensor = ArbitraryTensor::arbitrary(&mut rng);

        assert!(all_finite(&tensor));
        assert_eq!(tensor.data.len(), tensor.shape.iter().product::<usize>());
    }
}
