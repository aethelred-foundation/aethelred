//! Aethelred SDK Testing Framework
//!
//! A comprehensive testing framework for the Aethelred AI Blockchain SDK.
//! Provides unit testing, integration testing, property-based testing,
//! and benchmarking capabilities.
//!
//! # Features
//!
//! - Unit testing with assertions and mocking
//! - Integration testing with test fixtures
//! - Property-based testing (fuzzing)
//! - Snapshot testing for model outputs
//! - Performance regression testing
//! - Coverage analysis
//! - Test discovery and filtering
//! - Parallel test execution
//! - Test reporting (JUnit, TAP, JSON)

pub mod assertions;
pub mod fixtures;
pub mod mocking;
pub mod property;
pub mod snapshot;
pub mod runner;
pub mod reporter;
pub mod coverage;

use std::collections::HashMap;
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ============ Test Result ============

/// Result of a test execution
#[derive(Debug, Clone)]
pub enum TestResult {
    Passed {
        duration: Duration,
    },
    Failed {
        message: String,
        location: Option<String>,
        duration: Duration,
    },
    Skipped {
        reason: String,
    },
    TimedOut {
        timeout: Duration,
    },
}

impl TestResult {
    pub fn is_passed(&self) -> bool {
        matches!(self, TestResult::Passed { .. })
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, TestResult::Failed { .. })
    }

    pub fn is_skipped(&self) -> bool {
        matches!(self, TestResult::Skipped { .. })
    }
}

// ============ Test Case ============

/// A single test case
pub struct TestCase {
    pub name: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub timeout: Option<Duration>,
    pub retries: u32,
    pub should_panic: bool,
    pub func: Box<dyn Fn() -> Result<(), Box<dyn std::error::Error>> + Send + Sync>,
}

impl TestCase {
    /// Create a new test case
    pub fn new<F>(name: impl Into<String>, func: F) -> Self
    where
        F: Fn() -> Result<(), Box<dyn std::error::Error>> + Send + Sync + 'static,
    {
        TestCase {
            name: name.into(),
            description: None,
            tags: Vec::new(),
            timeout: None,
            retries: 0,
            should_panic: false,
            func: Box::new(func),
        }
    }

    /// Set test description
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Add a tag
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set retry count
    pub fn retries(mut self, count: u32) -> Self {
        self.retries = count;
        self
    }

    /// Mark as should panic
    pub fn should_panic(mut self) -> Self {
        self.should_panic = true;
        self
    }

    /// Run the test
    pub fn run(&self) -> TestResult {
        let start = Instant::now();

        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            (self.func)()
        }));

        let duration = start.elapsed();

        match result {
            Ok(Ok(())) => {
                if self.should_panic {
                    TestResult::Failed {
                        message: "Expected panic but test passed".to_string(),
                        location: None,
                        duration,
                    }
                } else {
                    TestResult::Passed { duration }
                }
            }
            Ok(Err(e)) => TestResult::Failed {
                message: e.to_string(),
                location: None,
                duration,
            },
            Err(panic_info) => {
                if self.should_panic {
                    TestResult::Passed { duration }
                } else {
                    let message = if let Some(s) = panic_info.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic_info.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "Unknown panic".to_string()
                    };

                    TestResult::Failed {
                        message,
                        location: None,
                        duration,
                    }
                }
            }
        }
    }
}

// ============ Test Suite ============

/// A collection of tests
pub struct TestSuite {
    pub name: String,
    pub tests: Vec<TestCase>,
    pub setup: Option<Box<dyn Fn() + Send + Sync>>,
    pub teardown: Option<Box<dyn Fn() + Send + Sync>>,
    pub before_each: Option<Box<dyn Fn() + Send + Sync>>,
    pub after_each: Option<Box<dyn Fn() + Send + Sync>>,
}

impl TestSuite {
    /// Create a new test suite
    pub fn new(name: impl Into<String>) -> Self {
        TestSuite {
            name: name.into(),
            tests: Vec::new(),
            setup: None,
            teardown: None,
            before_each: None,
            after_each: None,
        }
    }

    /// Add a test case
    pub fn add(&mut self, test: TestCase) -> &mut Self {
        self.tests.push(test);
        self
    }

    /// Set setup function
    pub fn setup<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.setup = Some(Box::new(f));
        self
    }

    /// Set teardown function
    pub fn teardown<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.teardown = Some(Box::new(f));
        self
    }

    /// Set before_each function
    pub fn before_each<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.before_each = Some(Box::new(f));
        self
    }

    /// Set after_each function
    pub fn after_each<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.after_each = Some(Box::new(f));
        self
    }

    /// Run all tests in the suite
    pub fn run(&self) -> SuiteResult {
        let mut results = Vec::new();
        let start = Instant::now();

        // Run setup
        if let Some(ref setup) = self.setup {
            setup();
        }

        for test in &self.tests {
            // Run before_each
            if let Some(ref before_each) = self.before_each {
                before_each();
            }

            // Run test with retries
            let mut result = test.run();
            let mut attempts = 1;

            while result.is_failed() && attempts <= test.retries {
                result = test.run();
                attempts += 1;
            }

            results.push((test.name.clone(), result));

            // Run after_each
            if let Some(ref after_each) = self.after_each {
                after_each();
            }
        }

        // Run teardown
        if let Some(ref teardown) = self.teardown {
            teardown();
        }

        SuiteResult {
            name: self.name.clone(),
            results,
            duration: start.elapsed(),
        }
    }
}

/// Result of running a test suite
#[derive(Debug)]
pub struct SuiteResult {
    pub name: String,
    pub results: Vec<(String, TestResult)>,
    pub duration: Duration,
}

impl SuiteResult {
    /// Get number of passed tests
    pub fn passed(&self) -> usize {
        self.results.iter().filter(|(_, r)| r.is_passed()).count()
    }

    /// Get number of failed tests
    pub fn failed(&self) -> usize {
        self.results.iter().filter(|(_, r)| r.is_failed()).count()
    }

    /// Get number of skipped tests
    pub fn skipped(&self) -> usize {
        self.results.iter().filter(|(_, r)| r.is_skipped()).count()
    }

    /// Get total number of tests
    pub fn total(&self) -> usize {
        self.results.len()
    }

    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.failed() == 0
    }
}

// ============ Test Runner ============

/// Configuration for the test runner
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Filter tests by name pattern
    pub filter: Option<String>,

    /// Filter tests by tag
    pub tags: Vec<String>,

    /// Number of parallel test threads
    pub parallel: usize,

    /// Default timeout for tests
    pub timeout: Duration,

    /// Output format
    pub format: OutputFormat,

    /// Show verbose output
    pub verbose: bool,

    /// Fail fast on first failure
    pub fail_fast: bool,

    /// Shuffle test order
    pub shuffle: bool,

    /// Random seed for shuffling
    pub seed: Option<u64>,
}

impl Default for TestConfig {
    fn default() -> Self {
        TestConfig {
            filter: None,
            tags: Vec::new(),
            parallel: num_cpus::get(),
            timeout: Duration::from_secs(60),
            format: OutputFormat::Pretty,
            verbose: false,
            fail_fast: false,
            shuffle: false,
            seed: None,
        }
    }
}

/// Output format for test results
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Pretty,
    Compact,
    Json,
    JUnit,
    Tap,
}

/// Test runner
pub struct TestRunner {
    config: TestConfig,
    suites: Vec<TestSuite>,
}

impl TestRunner {
    /// Create a new test runner
    pub fn new(config: TestConfig) -> Self {
        TestRunner {
            config,
            suites: Vec::new(),
        }
    }

    /// Add a test suite
    pub fn add_suite(&mut self, suite: TestSuite) -> &mut Self {
        self.suites.push(suite);
        self
    }

    /// Run all tests
    pub fn run(&self) -> RunResult {
        let start = Instant::now();
        let mut suite_results = Vec::new();

        for suite in &self.suites {
            let result = suite.run();
            suite_results.push(result);

            if self.config.fail_fast {
                if let Some(last) = suite_results.last() {
                    if last.failed() > 0 {
                        break;
                    }
                }
            }
        }

        RunResult {
            suites: suite_results,
            duration: start.elapsed(),
            config: self.config.clone(),
        }
    }
}

/// Result of running all tests
#[derive(Debug)]
pub struct RunResult {
    pub suites: Vec<SuiteResult>,
    pub duration: Duration,
    pub config: TestConfig,
}

impl RunResult {
    /// Get total passed tests
    pub fn total_passed(&self) -> usize {
        self.suites.iter().map(|s| s.passed()).sum()
    }

    /// Get total failed tests
    pub fn total_failed(&self) -> usize {
        self.suites.iter().map(|s| s.failed()).sum()
    }

    /// Get total skipped tests
    pub fn total_skipped(&self) -> usize {
        self.suites.iter().map(|s| s.skipped()).sum()
    }

    /// Get total tests
    pub fn total_tests(&self) -> usize {
        self.suites.iter().map(|s| s.total()).sum()
    }

    /// Check if all tests passed
    pub fn success(&self) -> bool {
        self.total_failed() == 0
    }

    /// Get exit code
    pub fn exit_code(&self) -> i32 {
        if self.success() { 0 } else { 1 }
    }
}

// ============ Macros ============

/// Assert that two values are equal
#[macro_export]
macro_rules! assert_eq_aethelred {
    ($left:expr, $right:expr) => {
        if $left != $right {
            panic!("assertion failed: `(left == right)`\n  left: `{:?}`,\n right: `{:?}`", $left, $right);
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        if $left != $right {
            panic!("assertion failed: `(left == right)`\n  left: `{:?}`,\n right: `{:?}`\n{}", $left, $right, format_args!($($arg)+));
        }
    };
}

/// Assert that two tensors are approximately equal
#[macro_export]
macro_rules! assert_tensor_eq {
    ($left:expr, $right:expr) => {
        $crate::assertions::assert_tensors_equal(&$left, &$right, 1e-6);
    };
    ($left:expr, $right:expr, $tol:expr) => {
        $crate::assertions::assert_tensors_equal(&$left, &$right, $tol);
    };
}

/// Assert that a tensor has the expected shape
#[macro_export]
macro_rules! assert_shape {
    ($tensor:expr, $shape:expr) => {
        assert_eq!($tensor.shape(), &$shape, "Tensor shape mismatch");
    };
}

/// Skip a test with a reason
#[macro_export]
macro_rules! skip {
    ($reason:expr) => {
        return Err(Box::new($crate::SkipError::new($reason)));
    };
}

/// Create a test case
#[macro_export]
macro_rules! test {
    ($name:expr, $body:expr) => {
        $crate::TestCase::new($name, || {
            $body;
            Ok(())
        })
    };
}

/// Skip error
#[derive(Debug)]
pub struct SkipError {
    reason: String,
}

impl SkipError {
    pub fn new(reason: impl Into<String>) -> Self {
        SkipError { reason: reason.into() }
    }
}

impl fmt::Display for SkipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Test skipped: {}", self.reason)
    }
}

impl std::error::Error for SkipError {}

// ============ Test Utilities ============

/// Create a temporary directory for tests
pub fn temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("Failed to create temp directory")
}

/// Create a test tensor with random data
pub fn random_tensor(shape: &[usize]) -> Vec<f32> {
    use rand::Rng;
    let size: usize = shape.iter().product();
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen::<f32>()).collect()
}

/// Create a test tensor with zeros
pub fn zeros_tensor(shape: &[usize]) -> Vec<f32> {
    let size: usize = shape.iter().product();
    vec![0.0; size]
}

/// Create a test tensor with ones
pub fn ones_tensor(shape: &[usize]) -> Vec<f32> {
    let size: usize = shape.iter().product();
    vec![1.0; size]
}

/// Time a function execution
pub fn time_it<F, T>(f: F) -> (T, Duration)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    (result, start.elapsed())
}
