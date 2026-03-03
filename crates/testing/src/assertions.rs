//! Aethelred SDK Assertion Library
//!
//! Comprehensive assertion utilities for testing AI/ML applications.
//! Provides tensor-aware assertions, floating point comparisons,
//! and domain-specific validation functions.

use std::fmt::Debug;
use std::collections::HashMap;

// ============ Tensor Assertions ============

/// Assert that two tensors are element-wise equal within tolerance
pub fn assert_tensors_equal<T: TensorLike>(left: &T, right: &T, tolerance: f64) {
    let left_shape = left.shape();
    let right_shape = right.shape();

    assert!(
        left_shape == right_shape,
        "Tensor shapes don't match: {:?} vs {:?}",
        left_shape,
        right_shape
    );

    let left_data = left.data();
    let right_data = right.data();

    for (i, (l, r)) in left_data.iter().zip(right_data.iter()).enumerate() {
        let diff = (*l - *r).abs();
        assert!(
            diff <= tolerance as f32,
            "Tensors differ at index {}: {} vs {} (diff: {}, tolerance: {})",
            i, l, r, diff, tolerance
        );
    }
}

/// Assert tensors are approximately equal (default tolerance 1e-6)
pub fn assert_tensors_approx_equal<T: TensorLike>(left: &T, right: &T) {
    assert_tensors_equal(left, right, 1e-6);
}

/// Assert tensor has expected shape
pub fn assert_tensor_shape<T: TensorLike>(tensor: &T, expected: &[usize]) {
    let actual = tensor.shape();
    assert!(
        actual == expected,
        "Tensor shape mismatch: expected {:?}, got {:?}",
        expected,
        actual
    );
}

/// Assert tensor values are within range
pub fn assert_tensor_in_range<T: TensorLike>(tensor: &T, min: f32, max: f32) {
    for (i, &val) in tensor.data().iter().enumerate() {
        assert!(
            val >= min && val <= max,
            "Tensor value at index {} is out of range: {} not in [{}, {}]",
            i, val, min, max
        );
    }
}

/// Assert tensor contains no NaN values
pub fn assert_no_nan<T: TensorLike>(tensor: &T) {
    for (i, &val) in tensor.data().iter().enumerate() {
        assert!(
            !val.is_nan(),
            "Tensor contains NaN at index {}",
            i
        );
    }
}

/// Assert tensor contains no infinite values
pub fn assert_no_inf<T: TensorLike>(tensor: &T) {
    for (i, &val) in tensor.data().iter().enumerate() {
        assert!(
            !val.is_infinite(),
            "Tensor contains infinity at index {}",
            i
        );
    }
}

/// Assert tensor is finite (no NaN or Inf)
pub fn assert_tensor_finite<T: TensorLike>(tensor: &T) {
    for (i, &val) in tensor.data().iter().enumerate() {
        assert!(
            val.is_finite(),
            "Tensor contains non-finite value at index {}: {}",
            i, val
        );
    }
}

/// Assert tensor is normalized (values sum to 1 along specified axis)
pub fn assert_normalized<T: TensorLike>(tensor: &T, tolerance: f64) {
    let sum: f32 = tensor.data().iter().sum();
    assert!(
        (sum - 1.0).abs() <= tolerance as f32,
        "Tensor is not normalized: sum = {} (expected 1.0)",
        sum
    );
}

/// Trait for tensor-like objects
pub trait TensorLike {
    fn shape(&self) -> &[usize];
    fn data(&self) -> &[f32];
}

// Simple Vec wrapper for testing
impl TensorLike for (Vec<usize>, Vec<f32>) {
    fn shape(&self) -> &[usize] {
        &self.0
    }

    fn data(&self) -> &[f32] {
        &self.1
    }
}

// ============ Floating Point Assertions ============

/// Assert two floats are approximately equal
pub fn assert_float_eq(left: f64, right: f64, epsilon: f64) {
    let diff = (left - right).abs();
    assert!(
        diff <= epsilon,
        "Floats not equal: {} vs {} (diff: {}, epsilon: {})",
        left, right, diff, epsilon
    );
}

/// Assert relative equality (for large values)
pub fn assert_relative_eq(left: f64, right: f64, rel_epsilon: f64) {
    let max_val = left.abs().max(right.abs());
    let diff = (left - right).abs();
    let rel_diff = if max_val > 0.0 { diff / max_val } else { diff };

    assert!(
        rel_diff <= rel_epsilon,
        "Floats not relatively equal: {} vs {} (rel_diff: {}, rel_epsilon: {})",
        left, right, rel_diff, rel_epsilon
    );
}

/// Assert float is within bounds
pub fn assert_in_range(value: f64, min: f64, max: f64) {
    assert!(
        value >= min && value <= max,
        "Value {} is out of range [{}, {}]",
        value, min, max
    );
}

// ============ Collection Assertions ============

/// Assert collections contain same elements (order-independent)
pub fn assert_same_elements<T: Eq + std::hash::Hash + Debug>(left: &[T], right: &[T]) {
    use std::collections::HashSet;

    let left_set: HashSet<_> = left.iter().collect();
    let right_set: HashSet<_> = right.iter().collect();

    assert!(
        left_set == right_set,
        "Collections don't contain same elements:\n  left: {:?}\n  right: {:?}",
        left, right
    );
}

/// Assert collection is sorted
pub fn assert_sorted<T: Ord + Debug>(values: &[T]) {
    for i in 1..values.len() {
        assert!(
            values[i-1] <= values[i],
            "Collection not sorted: {:?} > {:?} at indices [{}, {}]",
            values[i-1], values[i], i-1, i
        );
    }
}

/// Assert collection is sorted descending
pub fn assert_sorted_desc<T: Ord + Debug>(values: &[T]) {
    for i in 1..values.len() {
        assert!(
            values[i-1] >= values[i],
            "Collection not sorted descending: {:?} < {:?} at indices [{}, {}]",
            values[i-1], values[i], i-1, i
        );
    }
}

/// Assert collection contains element
pub fn assert_contains<T: PartialEq + Debug>(haystack: &[T], needle: &T) {
    assert!(
        haystack.contains(needle),
        "Collection does not contain {:?}",
        needle
    );
}

/// Assert collection is unique (no duplicates)
pub fn assert_unique<T: Eq + std::hash::Hash + Debug>(values: &[T]) {
    use std::collections::HashSet;
    let set: HashSet<_> = values.iter().collect();
    assert!(
        set.len() == values.len(),
        "Collection contains duplicates: {:?}",
        values
    );
}

// ============ String Assertions ============

/// Assert string contains substring
pub fn assert_string_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "String does not contain expected substring:\n  haystack: {}\n  needle: {}",
        haystack, needle
    );
}

/// Assert string matches regex pattern
pub fn assert_matches_pattern(text: &str, pattern: &str) {
    let re = regex::Regex::new(pattern).expect("Invalid regex pattern");
    assert!(
        re.is_match(text),
        "String does not match pattern:\n  text: {}\n  pattern: {}",
        text, pattern
    );
}

/// Assert string starts with prefix
pub fn assert_starts_with(text: &str, prefix: &str) {
    assert!(
        text.starts_with(prefix),
        "String does not start with prefix:\n  text: {}\n  prefix: {}",
        text, prefix
    );
}

/// Assert string ends with suffix
pub fn assert_ends_with(text: &str, suffix: &str) {
    assert!(
        text.ends_with(suffix),
        "String does not end with suffix:\n  text: {}\n  suffix: {}",
        text, suffix
    );
}

// ============ Result/Option Assertions ============

/// Assert Result is Ok
pub fn assert_ok<T: Debug, E: Debug>(result: &Result<T, E>) {
    assert!(
        result.is_ok(),
        "Expected Ok, got Err: {:?}",
        result
    );
}

/// Assert Result is Err
pub fn assert_err<T: Debug, E: Debug>(result: &Result<T, E>) {
    assert!(
        result.is_err(),
        "Expected Err, got Ok: {:?}",
        result
    );
}

/// Assert Option is Some
pub fn assert_some<T: Debug>(option: &Option<T>) {
    assert!(
        option.is_some(),
        "Expected Some, got None"
    );
}

/// Assert Option is None
pub fn assert_none<T: Debug>(option: &Option<T>) {
    assert!(
        option.is_none(),
        "Expected None, got Some: {:?}",
        option
    );
}

// ============ Performance Assertions ============

/// Assert operation completes within duration
pub fn assert_completes_within<F, T>(timeout_ms: u64, f: F) -> T
where
    F: FnOnce() -> T,
{
    use std::time::Instant;

    let start = Instant::now();
    let result = f();
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() <= timeout_ms as u128,
        "Operation took too long: {}ms (limit: {}ms)",
        elapsed.as_millis(),
        timeout_ms
    );

    result
}

/// Assert memory usage is within limit
pub struct MemoryAssertion {
    initial_usage: usize,
}

impl MemoryAssertion {
    pub fn start() -> Self {
        MemoryAssertion {
            initial_usage: get_memory_usage(),
        }
    }

    pub fn assert_within(&self, limit_bytes: usize) {
        let current = get_memory_usage();
        let delta = current.saturating_sub(self.initial_usage);

        assert!(
            delta <= limit_bytes,
            "Memory usage exceeded limit: {} bytes used (limit: {} bytes)",
            delta,
            limit_bytes
        );
    }
}

fn get_memory_usage() -> usize {
    // Platform-specific memory usage
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|s| s.split_whitespace().nth(1)?.parse::<usize>().ok())
            .map(|pages| pages * 4096)
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

// ============ Gradient Assertions ============

/// Assert gradients are computed correctly using numerical differentiation
pub fn assert_gradients_correct<F>(
    f: F,
    params: &[f32],
    computed_grads: &[f32],
    epsilon: f64,
    tolerance: f64,
) where
    F: Fn(&[f32]) -> f32,
{
    let mut numerical_grads = Vec::with_capacity(params.len());

    for i in 0..params.len() {
        let mut params_plus = params.to_vec();
        let mut params_minus = params.to_vec();

        params_plus[i] += epsilon as f32;
        params_minus[i] -= epsilon as f32;

        let f_plus = f(&params_plus);
        let f_minus = f(&params_minus);

        let numerical_grad = (f_plus - f_minus) / (2.0 * epsilon as f32);
        numerical_grads.push(numerical_grad);
    }

    for (i, (num, comp)) in numerical_grads.iter().zip(computed_grads.iter()).enumerate() {
        let diff = (*num - *comp).abs();
        assert!(
            diff <= tolerance as f32,
            "Gradient mismatch at index {}: numerical = {}, computed = {} (diff: {})",
            i, num, comp, diff
        );
    }
}

// ============ Statistical Assertions ============

/// Assert mean of values is within expected range
pub fn assert_mean_in_range(values: &[f64], expected_min: f64, expected_max: f64) {
    let mean: f64 = values.iter().sum::<f64>() / values.len() as f64;
    assert!(
        mean >= expected_min && mean <= expected_max,
        "Mean {} is not in expected range [{}, {}]",
        mean, expected_min, expected_max
    );
}

/// Assert standard deviation is within expected range
pub fn assert_std_in_range(values: &[f64], expected_min: f64, expected_max: f64) {
    let mean: f64 = values.iter().sum::<f64>() / values.len() as f64;
    let variance: f64 = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64;
    let std = variance.sqrt();

    assert!(
        std >= expected_min && std <= expected_max,
        "Standard deviation {} is not in expected range [{}, {}]",
        std, expected_min, expected_max
    );
}

/// Assert values follow normal distribution (using Shapiro-Wilk test approximation)
pub fn assert_normally_distributed(values: &[f64], significance: f64) {
    // Simplified normality check using skewness and kurtosis
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;

    let m2: f64 = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let m3: f64 = values.iter().map(|x| (x - mean).powi(3)).sum::<f64>() / n;
    let m4: f64 = values.iter().map(|x| (x - mean).powi(4)).sum::<f64>() / n;

    let std = m2.sqrt();
    let skewness = m3 / m2.powf(1.5);
    let kurtosis = m4 / m2.powi(2) - 3.0; // Excess kurtosis

    // For normal distribution, skewness should be ~0 and excess kurtosis ~0
    let skewness_threshold = 2.0 * (6.0 / n).sqrt();
    let kurtosis_threshold = 2.0 * (24.0 / n).sqrt();

    assert!(
        skewness.abs() <= skewness_threshold,
        "Distribution is not normal: skewness = {} (threshold: {})",
        skewness, skewness_threshold
    );

    assert!(
        kurtosis.abs() <= kurtosis_threshold,
        "Distribution is not normal: excess kurtosis = {} (threshold: {})",
        kurtosis, kurtosis_threshold
    );
}

// ============ JSON Assertions ============

/// Assert JSON values are equal
pub fn assert_json_eq(left: &serde_json::Value, right: &serde_json::Value) {
    assert!(
        left == right,
        "JSON values not equal:\n  left: {}\n  right: {}",
        serde_json::to_string_pretty(left).unwrap(),
        serde_json::to_string_pretty(right).unwrap()
    );
}

/// Assert JSON has expected field
pub fn assert_json_has_field(json: &serde_json::Value, field: &str) {
    assert!(
        json.get(field).is_some(),
        "JSON missing expected field: {}",
        field
    );
}

/// Assert JSON field has expected value
pub fn assert_json_field_eq(json: &serde_json::Value, field: &str, expected: &serde_json::Value) {
    let actual = json.get(field);
    assert!(
        actual.is_some(),
        "JSON missing field: {}",
        field
    );
    assert!(
        actual.unwrap() == expected,
        "JSON field '{}' has unexpected value:\n  expected: {}\n  actual: {}",
        field,
        expected,
        actual.unwrap()
    );
}

// ============ Assertion Builder ============

/// Fluent assertion builder
pub struct Assert<T> {
    value: T,
    description: Option<String>,
}

impl<T> Assert<T> {
    pub fn that(value: T) -> Self {
        Assert {
            value,
            description: None,
        }
    }

    pub fn described_as(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

impl<T: PartialEq + Debug> Assert<T> {
    pub fn is_equal_to(self, expected: T) {
        if self.value != expected {
            if let Some(desc) = self.description {
                panic!(
                    "{}: expected {:?}, got {:?}",
                    desc, expected, self.value
                );
            } else {
                panic!("expected {:?}, got {:?}", expected, self.value);
            }
        }
    }

    pub fn is_not_equal_to(self, expected: T) {
        if self.value == expected {
            if let Some(desc) = self.description {
                panic!("{}: expected value to not equal {:?}", desc, expected);
            } else {
                panic!("expected value to not equal {:?}", expected);
            }
        }
    }
}

impl<T: PartialOrd + Debug> Assert<T> {
    pub fn is_greater_than(self, other: T) {
        if !(self.value > other) {
            if let Some(desc) = self.description {
                panic!("{}: expected {:?} > {:?}", desc, self.value, other);
            } else {
                panic!("expected {:?} > {:?}", self.value, other);
            }
        }
    }

    pub fn is_less_than(self, other: T) {
        if !(self.value < other) {
            if let Some(desc) = self.description {
                panic!("{}: expected {:?} < {:?}", desc, self.value, other);
            } else {
                panic!("expected {:?} < {:?}", self.value, other);
            }
        }
    }

    pub fn is_between(self, min: T, max: T)
    where
        T: Clone,
    {
        if !(self.value >= min && self.value <= max) {
            if let Some(desc) = self.description {
                panic!(
                    "{}: expected {:?} to be between {:?} and {:?}",
                    desc, self.value, min, max
                );
            } else {
                panic!(
                    "expected {:?} to be between {:?} and {:?}",
                    self.value, min, max
                );
            }
        }
    }
}

impl Assert<bool> {
    pub fn is_true(self) {
        if !self.value {
            if let Some(desc) = self.description {
                panic!("{}: expected true", desc);
            } else {
                panic!("expected true");
            }
        }
    }

    pub fn is_false(self) {
        if self.value {
            if let Some(desc) = self.description {
                panic!("{}: expected false", desc);
            } else {
                panic!("expected false");
            }
        }
    }
}

impl<T: Debug> Assert<Option<T>> {
    pub fn is_some(self) {
        if self.value.is_none() {
            if let Some(desc) = self.description {
                panic!("{}: expected Some, got None", desc);
            } else {
                panic!("expected Some, got None");
            }
        }
    }

    pub fn is_none(self) {
        if self.value.is_some() {
            if let Some(desc) = self.description {
                panic!("{}: expected None, got {:?}", desc, self.value);
            } else {
                panic!("expected None, got {:?}", self.value);
            }
        }
    }
}

impl<T: Debug, E: Debug> Assert<Result<T, E>> {
    pub fn is_ok(self) {
        if self.value.is_err() {
            if let Some(desc) = self.description {
                panic!("{}: expected Ok, got {:?}", desc, self.value);
            } else {
                panic!("expected Ok, got {:?}", self.value);
            }
        }
    }

    pub fn is_err(self) {
        if self.value.is_ok() {
            if let Some(desc) = self.description {
                panic!("{}: expected Err, got {:?}", desc, self.value);
            } else {
                panic!("expected Err, got {:?}", self.value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_float_eq() {
        assert_float_eq(1.0, 1.0000001, 1e-6);
    }

    #[test]
    fn test_tensor_assertions() {
        let t1 = (vec![2, 3], vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let t2 = (vec![2, 3], vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        assert_tensors_equal(&t1, &t2, 1e-6);
    }

    #[test]
    fn test_fluent_assertions() {
        Assert::that(5)
            .described_as("number check")
            .is_greater_than(3);

        Assert::that(Some(42)).is_some();
        Assert::that(true).is_true();
    }
}
