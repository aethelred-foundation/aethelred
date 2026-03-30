//! Aethelred SDK Mocking Framework
//!
//! Comprehensive mocking utilities for testing AI/ML applications.
//! Supports mock objects, spies, stubs, and behavior verification.

use std::any::Any;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex, RwLock};

// ============ Mock Registry ============

/// Thread-local mock registry
thread_local! {
    static MOCK_REGISTRY: RwLock<MockRegistry> = RwLock::new(MockRegistry::new());
}

/// Registry for managing mocks
pub struct MockRegistry {
    mocks: HashMap<String, Arc<dyn Any + Send + Sync>>,
    call_records: HashMap<String, Vec<CallRecord>>,
}

impl MockRegistry {
    pub fn new() -> Self {
        MockRegistry {
            mocks: HashMap::new(),
            call_records: HashMap::new(),
        }
    }

    pub fn register<T: Any + Send + Sync>(&mut self, name: &str, mock: T) {
        self.mocks.insert(name.to_string(), Arc::new(mock));
        self.call_records.insert(name.to_string(), Vec::new());
    }

    pub fn get<T: Any + Send + Sync + Clone>(&self, name: &str) -> Option<T> {
        self.mocks
            .get(name)
            .and_then(|m| m.downcast_ref::<T>().cloned())
    }

    pub fn record_call(&mut self, name: &str, record: CallRecord) {
        if let Some(records) = self.call_records.get_mut(name) {
            records.push(record);
        }
    }

    pub fn get_calls(&self, name: &str) -> Option<&Vec<CallRecord>> {
        self.call_records.get(name)
    }

    pub fn clear(&mut self) {
        self.mocks.clear();
        self.call_records.clear();
    }
}

impl Default for MockRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Record of a mock call
#[derive(Debug, Clone)]
pub struct CallRecord {
    pub method: String,
    pub args: Vec<String>,
    pub timestamp: std::time::Instant,
}

impl CallRecord {
    pub fn new(method: &str, args: Vec<String>) -> Self {
        CallRecord {
            method: method.to_string(),
            args,
            timestamp: std::time::Instant::now(),
        }
    }
}

// ============ Mock Builder ============

/// Builder for creating mock objects
pub struct MockBuilder<T> {
    name: String,
    behaviors: Vec<Box<dyn Fn(&[Box<dyn Any>]) -> Option<Box<dyn Any>> + Send + Sync>>,
    expectations: Vec<Expectation>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> MockBuilder<T> {
    pub fn new(name: impl Into<String>) -> Self {
        MockBuilder {
            name: name.into(),
            behaviors: Vec::new(),
            expectations: Vec::new(),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set a return value for a method
    pub fn when_called(self, method: &str) -> ExpectationBuilder<T> {
        ExpectationBuilder {
            mock_builder: self,
            method: method.to_string(),
            args_matcher: None,
            times: None,
        }
    }
}

/// Builder for setting expectations
pub struct ExpectationBuilder<T> {
    mock_builder: MockBuilder<T>,
    method: String,
    args_matcher: Option<Box<dyn Fn(&[Box<dyn Any>]) -> bool + Send + Sync>>,
    times: Option<Times>,
}

impl<T> ExpectationBuilder<T> {
    pub fn with_args<F>(mut self, matcher: F) -> Self
    where
        F: Fn(&[Box<dyn Any>]) -> bool + Send + Sync + 'static,
    {
        self.args_matcher = Some(Box::new(matcher));
        self
    }

    pub fn times(mut self, times: Times) -> Self {
        self.times = Some(times);
        self
    }

    pub fn returns<R: Any + Clone + Send + Sync + 'static>(mut self, value: R) -> MockBuilder<T> {
        let method = self.method.clone();
        let expectation = Expectation {
            method: method.clone(),
            times: self.times.unwrap_or(Times::Any),
            call_count: Arc::new(Mutex::new(0)),
        };

        self.mock_builder.expectations.push(expectation);

        let value = Arc::new(value);
        self.mock_builder.behaviors.push(Box::new(move |_| {
            Some(Box::new((*value).clone()) as Box<dyn Any>)
        }));

        self.mock_builder
    }

    pub fn returns_fn<R, F>(mut self, f: F) -> MockBuilder<T>
    where
        R: Any + 'static,
        F: Fn() -> R + Send + Sync + 'static,
    {
        let method = self.method.clone();
        let expectation = Expectation {
            method: method.clone(),
            times: self.times.unwrap_or(Times::Any),
            call_count: Arc::new(Mutex::new(0)),
        };

        self.mock_builder.expectations.push(expectation);

        self.mock_builder
            .behaviors
            .push(Box::new(move |_| Some(Box::new(f()) as Box<dyn Any>)));

        self.mock_builder
    }

    pub fn panics(self, message: &str) -> MockBuilder<T> {
        let msg = message.to_string();
        let method = self.method.clone();
        let expectation = Expectation {
            method,
            times: self.times.unwrap_or(Times::Any),
            call_count: Arc::new(Mutex::new(0)),
        };

        let mut mock_builder = self.mock_builder;
        mock_builder.expectations.push(expectation);

        mock_builder.behaviors.push(Box::new(move |_| {
            panic!("{}", msg);
        }));

        mock_builder
    }
}

/// Expectation for mock verification
#[derive(Clone)]
pub struct Expectation {
    pub method: String,
    pub times: Times,
    pub call_count: Arc<Mutex<usize>>,
}

impl Expectation {
    pub fn verify(&self) -> Result<(), String> {
        let count = *self.call_count.lock().unwrap();
        match self.times {
            Times::Exactly(n) if count != n => Err(format!(
                "Expected {} to be called exactly {} times, but was called {} times",
                self.method, n, count
            )),
            Times::AtLeast(n) if count < n => Err(format!(
                "Expected {} to be called at least {} times, but was called {} times",
                self.method, n, count
            )),
            Times::AtMost(n) if count > n => Err(format!(
                "Expected {} to be called at most {} times, but was called {} times",
                self.method, n, count
            )),
            Times::Never if count > 0 => Err(format!(
                "Expected {} to never be called, but was called {} times",
                self.method, count
            )),
            _ => Ok(()),
        }
    }
}

/// Specifies how many times a method should be called
#[derive(Clone, Copy, Debug)]
pub enum Times {
    Any,
    Exactly(usize),
    AtLeast(usize),
    AtMost(usize),
    Never,
    Once,
}

// ============ Mock Object ============

/// A mock object that tracks calls and returns configured values
pub struct Mock<T> {
    name: String,
    return_values: Arc<RwLock<HashMap<String, Vec<Box<dyn Any + Send + Sync>>>>>,
    call_history: Arc<Mutex<Vec<CallRecord>>>,
    expectations: Arc<RwLock<Vec<Expectation>>>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Mock<T> {
    pub fn new(name: impl Into<String>) -> Self {
        Mock {
            name: name.into(),
            return_values: Arc::new(RwLock::new(HashMap::new())),
            call_history: Arc::new(Mutex::new(Vec::new())),
            expectations: Arc::new(RwLock::new(Vec::new())),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Record a method call
    pub fn record_call(&self, method: &str, args: Vec<String>) {
        let record = CallRecord::new(method, args);
        self.call_history.lock().unwrap().push(record);

        // Update expectation call counts
        let expectations = self.expectations.read().unwrap();
        for exp in expectations.iter() {
            if exp.method == method {
                let mut count = exp.call_count.lock().unwrap();
                *count += 1;
            }
        }
    }

    /// Get number of times a method was called
    pub fn call_count(&self, method: &str) -> usize {
        self.call_history
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.method == method)
            .count()
    }

    /// Get all calls to a method
    pub fn calls(&self, method: &str) -> Vec<CallRecord> {
        self.call_history
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.method == method)
            .cloned()
            .collect()
    }

    /// Check if method was called
    pub fn was_called(&self, method: &str) -> bool {
        self.call_count(method) > 0
    }

    /// Check if method was called with specific arguments
    pub fn was_called_with(&self, method: &str, args: &[String]) -> bool {
        self.call_history
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.method == method && r.args == args)
    }

    /// Set return value for a method
    pub fn set_return<R: Any + Send + Sync + 'static>(&self, method: &str, value: R) {
        let mut values = self.return_values.write().unwrap();
        values
            .entry(method.to_string())
            .or_default()
            .push(Box::new(value));
    }

    /// Get return value for a method
    pub fn get_return<R: Any + Clone>(&self, method: &str) -> Option<R> {
        let mut values = self.return_values.write().unwrap();
        values.get_mut(method).and_then(|v| {
            if v.is_empty() {
                None
            } else {
                let val = v.remove(0);
                val.downcast_ref::<R>().cloned()
            }
        })
    }

    /// Add an expectation
    pub fn expect(&self, method: &str, times: Times) {
        let mut expectations = self.expectations.write().unwrap();
        expectations.push(Expectation {
            method: method.to_string(),
            times,
            call_count: Arc::new(Mutex::new(0)),
        });
    }

    /// Verify all expectations
    pub fn verify(&self) -> Result<(), Vec<String>> {
        let expectations = self.expectations.read().unwrap();
        let errors: Vec<String> = expectations
            .iter()
            .filter_map(|e| e.verify().err())
            .collect();

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Reset mock state
    pub fn reset(&self) {
        self.call_history.lock().unwrap().clear();
        self.return_values.write().unwrap().clear();
        self.expectations.write().unwrap().clear();
    }
}

impl<T> Clone for Mock<T> {
    fn clone(&self) -> Self {
        Mock {
            name: self.name.clone(),
            return_values: Arc::clone(&self.return_values),
            call_history: Arc::clone(&self.call_history),
            expectations: Arc::clone(&self.expectations),
            _phantom: std::marker::PhantomData,
        }
    }
}

// ============ Spy ============

/// A spy that wraps an object and tracks calls
pub struct Spy<T> {
    inner: T,
    call_history: Arc<Mutex<Vec<CallRecord>>>,
}

impl<T> Spy<T> {
    pub fn new(inner: T) -> Self {
        Spy {
            inner,
            call_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn record_call(&self, method: &str, args: Vec<String>) {
        let record = CallRecord::new(method, args);
        self.call_history.lock().unwrap().push(record);
    }

    pub fn call_count(&self, method: &str) -> usize {
        self.call_history
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.method == method)
            .count()
    }

    pub fn was_called(&self, method: &str) -> bool {
        self.call_count(method) > 0
    }

    pub fn calls(&self) -> Vec<CallRecord> {
        self.call_history.lock().unwrap().clone()
    }

    pub fn reset(&self) {
        self.call_history.lock().unwrap().clear();
    }
}

// ============ Stub ============

/// A stub that returns configured values
pub struct Stub<T> {
    values: HashMap<String, Box<dyn Any + Send + Sync>>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> Stub<T> {
    pub fn new() -> Self {
        Stub {
            values: HashMap::new(),
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn with<R: Any + Send + Sync + 'static>(mut self, method: &str, value: R) -> Self {
        self.values.insert(method.to_string(), Box::new(value));
        self
    }

    pub fn get<R: Any + Clone>(&self, method: &str) -> Option<R> {
        self.values
            .get(method)
            .and_then(|v| v.downcast_ref::<R>().cloned())
    }
}

impl<T> Default for Stub<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ============ Mock Tensor ============

/// Mock tensor for testing tensor operations
#[derive(Debug, Clone)]
pub struct MockTensor {
    pub shape: Vec<usize>,
    pub data: Vec<f32>,
    pub device: String,
    pub dtype: String,
    call_history: Arc<Mutex<Vec<CallRecord>>>,
}

impl MockTensor {
    pub fn new(shape: Vec<usize>) -> Self {
        let size: usize = shape.iter().product();
        MockTensor {
            shape,
            data: vec![0.0; size],
            device: "cpu".to_string(),
            dtype: "float32".to_string(),
            call_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_data(mut self, data: Vec<f32>) -> Self {
        self.data = data;
        self
    }

    pub fn with_device(mut self, device: &str) -> Self {
        self.device = device.to_string();
        self
    }

    pub fn add(&self, other: &MockTensor) -> MockTensor {
        self.call_history
            .lock()
            .unwrap()
            .push(CallRecord::new("add", vec![]));

        let data: Vec<f32> = self
            .data
            .iter()
            .zip(other.data.iter())
            .map(|(a, b)| a + b)
            .collect();

        MockTensor {
            shape: self.shape.clone(),
            data,
            device: self.device.clone(),
            dtype: self.dtype.clone(),
            call_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn mul(&self, other: &MockTensor) -> MockTensor {
        self.call_history
            .lock()
            .unwrap()
            .push(CallRecord::new("mul", vec![]));

        let data: Vec<f32> = self
            .data
            .iter()
            .zip(other.data.iter())
            .map(|(a, b)| a * b)
            .collect();

        MockTensor {
            shape: self.shape.clone(),
            data,
            device: self.device.clone(),
            dtype: self.dtype.clone(),
            call_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn matmul(&self, other: &MockTensor) -> MockTensor {
        self.call_history
            .lock()
            .unwrap()
            .push(CallRecord::new("matmul", vec![]));

        // Simplified 2D matmul
        assert!(self.shape.len() == 2 && other.shape.len() == 2);
        assert!(self.shape[1] == other.shape[0]);

        let m = self.shape[0];
        let k = self.shape[1];
        let n = other.shape[1];

        let mut result = vec![0.0; m * n];

        for i in 0..m {
            for j in 0..n {
                for l in 0..k {
                    result[i * n + j] += self.data[i * k + l] * other.data[l * n + j];
                }
            }
        }

        MockTensor {
            shape: vec![m, n],
            data: result,
            device: self.device.clone(),
            dtype: self.dtype.clone(),
            call_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn call_count(&self, method: &str) -> usize {
        self.call_history
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.method == method)
            .count()
    }
}

// ============ Mock Model ============

/// Mock model for testing model operations
pub struct MockModel {
    name: String,
    parameters: Arc<RwLock<HashMap<String, MockTensor>>>,
    call_history: Arc<Mutex<Vec<CallRecord>>>,
    forward_fn: Option<Box<dyn Fn(&MockTensor) -> MockTensor + Send + Sync>>,
}

impl MockModel {
    pub fn new(name: impl Into<String>) -> Self {
        MockModel {
            name: name.into(),
            parameters: Arc::new(RwLock::new(HashMap::new())),
            call_history: Arc::new(Mutex::new(Vec::new())),
            forward_fn: None,
        }
    }

    pub fn with_parameter(self, name: &str, tensor: MockTensor) -> Self {
        self.parameters
            .write()
            .unwrap()
            .insert(name.to_string(), tensor);
        self
    }

    pub fn with_forward<F>(mut self, f: F) -> Self
    where
        F: Fn(&MockTensor) -> MockTensor + Send + Sync + 'static,
    {
        self.forward_fn = Some(Box::new(f));
        self
    }

    pub fn forward(&self, input: &MockTensor) -> MockTensor {
        self.call_history
            .lock()
            .unwrap()
            .push(CallRecord::new("forward", vec![]));

        if let Some(ref f) = self.forward_fn {
            f(input)
        } else {
            input.clone()
        }
    }

    pub fn parameters(&self) -> Vec<MockTensor> {
        self.parameters.read().unwrap().values().cloned().collect()
    }

    pub fn call_count(&self, method: &str) -> usize {
        self.call_history
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.method == method)
            .count()
    }
}

// ============ Mock HTTP Client ============

/// Mock HTTP client for testing network operations
pub struct MockHttpClient {
    responses: Arc<RwLock<HashMap<String, MockResponse>>>,
    call_history: Arc<Mutex<Vec<CallRecord>>>,
}

#[derive(Clone)]
pub struct MockResponse {
    pub status: u16,
    pub body: String,
    pub headers: HashMap<String, String>,
}

impl MockHttpClient {
    pub fn new() -> Self {
        MockHttpClient {
            responses: Arc::new(RwLock::new(HashMap::new())),
            call_history: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn mock_get(&self, url: &str, response: MockResponse) {
        let key = format!("GET:{}", url);
        self.responses.write().unwrap().insert(key, response);
    }

    pub fn mock_post(&self, url: &str, response: MockResponse) {
        let key = format!("POST:{}", url);
        self.responses.write().unwrap().insert(key, response);
    }

    pub fn get(&self, url: &str) -> Option<MockResponse> {
        let record = CallRecord::new("get", vec![url.to_string()]);
        self.call_history.lock().unwrap().push(record);

        let key = format!("GET:{}", url);
        self.responses.read().unwrap().get(&key).cloned()
    }

    pub fn post(&self, url: &str, _body: &str) -> Option<MockResponse> {
        let record = CallRecord::new("post", vec![url.to_string()]);
        self.call_history.lock().unwrap().push(record);

        let key = format!("POST:{}", url);
        self.responses.read().unwrap().get(&key).cloned()
    }

    pub fn call_count(&self, method: &str) -> usize {
        self.call_history
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.method == method)
            .count()
    }

    pub fn verify_called(&self, method: &str, url: &str) -> bool {
        self.call_history
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.method == method && r.args.contains(&url.to_string()))
    }
}

impl Default for MockHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

// ============ Argument Matchers ============

/// Matchers for verifying arguments
pub mod matchers {

    pub fn any<T>() -> Box<dyn Fn(&T) -> bool + Send + Sync> {
        Box::new(|_| true)
    }

    pub fn eq<T: PartialEq + Send + Sync + 'static>(
        expected: T,
    ) -> Box<dyn Fn(&T) -> bool + Send + Sync> {
        Box::new(move |actual| *actual == expected)
    }

    pub fn in_range<T: PartialOrd + Send + Sync + 'static>(
        min: T,
        max: T,
    ) -> Box<dyn Fn(&T) -> bool + Send + Sync> {
        Box::new(move |actual| *actual >= min && *actual <= max)
    }

    pub fn satisfies<T: 'static, F: Fn(&T) -> bool + Send + Sync + 'static>(
        predicate: F,
    ) -> Box<dyn Fn(&T) -> bool + Send + Sync> {
        Box::new(move |actual| predicate(actual))
    }

    pub fn contains(substr: &str) -> Box<dyn Fn(&String) -> bool + Send + Sync> {
        let s = substr.to_string();
        Box::new(move |actual| actual.contains(&s))
    }

    pub fn starts_with(prefix: &str) -> Box<dyn Fn(&String) -> bool + Send + Sync> {
        let p = prefix.to_string();
        Box::new(move |actual| actual.starts_with(&p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_basic() {
        let mock: Mock<()> = Mock::new("test_mock");

        mock.set_return("get_value", 42i32);
        mock.record_call("get_value", vec![]);

        assert!(mock.was_called("get_value"));
        assert_eq!(mock.call_count("get_value"), 1);
    }

    #[test]
    fn test_mock_tensor() {
        let t1 = MockTensor::new(vec![2, 3]).with_data(vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
        let t2 = MockTensor::new(vec![2, 3]).with_data(vec![1.0, 1.0, 1.0, 1.0, 1.0, 1.0]);

        let result = t1.add(&t2);
        assert_eq!(result.data, vec![2.0, 3.0, 4.0, 5.0, 6.0, 7.0]);
    }

    #[test]
    fn test_spy() {
        let spy = Spy::new(vec![1, 2, 3]);
        spy.record_call("push", vec!["4".to_string()]);

        assert!(spy.was_called("push"));
        assert_eq!(spy.call_count("push"), 1);
    }
}
