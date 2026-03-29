//! Aethelred SDK Performance Benchmarking Suite
//!
//! Comprehensive benchmarking framework for AI/ML applications.
//! Provides inference benchmarks, training benchmarks, memory profiling,
//! network latency testing, and performance regression detection.
//!
//! # Features
//!
//! - Inference latency benchmarks (P50, P95, P99)
//! - Training throughput benchmarks
//! - Memory usage profiling
//! - GPU utilization tracking
//! - Network latency benchmarks
//! - Performance regression detection
//! - Comparison against baselines
//! - Multiple output formats (JSON, CSV, HTML)

pub mod hardware;
pub mod inference;
pub mod memory;
pub mod network;
pub mod regression;
pub mod reporter;
pub mod training;

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ============ Benchmark Result ============

/// Result of a single benchmark run
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub iterations: usize,
    pub total_time: Duration,
    pub samples: Vec<Duration>,
    pub metadata: HashMap<String, String>,
}

impl BenchmarkResult {
    pub fn new(name: impl Into<String>, samples: Vec<Duration>) -> Self {
        let total_time = samples.iter().sum();
        BenchmarkResult {
            name: name.into(),
            iterations: samples.len(),
            total_time,
            samples,
            metadata: HashMap::new(),
        }
    }

    /// Mean time per iteration
    pub fn mean(&self) -> Duration {
        if self.iterations == 0 {
            return Duration::ZERO;
        }
        self.total_time / self.iterations as u32
    }

    /// Median time
    pub fn median(&self) -> Duration {
        if self.samples.is_empty() {
            return Duration::ZERO;
        }
        let mut sorted = self.samples.clone();
        sorted.sort();
        sorted[sorted.len() / 2]
    }

    /// Standard deviation
    pub fn std_dev(&self) -> Duration {
        if self.samples.len() < 2 {
            return Duration::ZERO;
        }

        let mean_nanos = self.mean().as_nanos() as f64;
        let variance: f64 = self
            .samples
            .iter()
            .map(|s| {
                let diff = s.as_nanos() as f64 - mean_nanos;
                diff * diff
            })
            .sum::<f64>()
            / (self.samples.len() - 1) as f64;

        Duration::from_nanos(variance.sqrt() as u64)
    }

    /// Minimum time
    pub fn min(&self) -> Duration {
        self.samples.iter().min().copied().unwrap_or(Duration::ZERO)
    }

    /// Maximum time
    pub fn max(&self) -> Duration {
        self.samples.iter().max().copied().unwrap_or(Duration::ZERO)
    }

    /// Percentile (0-100)
    pub fn percentile(&self, p: f64) -> Duration {
        if self.samples.is_empty() {
            return Duration::ZERO;
        }
        let mut sorted = self.samples.clone();
        sorted.sort();
        let index = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        sorted[index.min(sorted.len() - 1)]
    }

    /// P50 latency
    pub fn p50(&self) -> Duration {
        self.percentile(50.0)
    }

    /// P95 latency
    pub fn p95(&self) -> Duration {
        self.percentile(95.0)
    }

    /// P99 latency
    pub fn p99(&self) -> Duration {
        self.percentile(99.0)
    }

    /// Throughput (iterations per second)
    pub fn throughput(&self) -> f64 {
        if self.total_time.as_secs_f64() == 0.0 {
            return 0.0;
        }
        self.iterations as f64 / self.total_time.as_secs_f64()
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

impl fmt::Display for BenchmarkResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: mean={:.2?}, median={:.2?}, std_dev={:.2?}, p95={:.2?}, p99={:.2?}, throughput={:.2}/s",
            self.name,
            self.mean(),
            self.median(),
            self.std_dev(),
            self.p95(),
            self.p99(),
            self.throughput()
        )
    }
}

// ============ Benchmark Suite ============

/// A collection of benchmarks
pub struct BenchmarkSuite {
    pub name: String,
    pub description: Option<String>,
    benchmarks: Vec<Box<dyn Benchmark>>,
    setup: Option<Box<dyn Fn() + Send + Sync>>,
    teardown: Option<Box<dyn Fn() + Send + Sync>>,
}

impl BenchmarkSuite {
    pub fn new(name: impl Into<String>) -> Self {
        BenchmarkSuite {
            name: name.into(),
            description: None,
            benchmarks: Vec::new(),
            setup: None,
            teardown: None,
        }
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn add<B: Benchmark + 'static>(mut self, benchmark: B) -> Self {
        self.benchmarks.push(Box::new(benchmark));
        self
    }

    pub fn setup<F>(mut self, f: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.setup = Some(Box::new(f));
        self
    }

    pub fn teardown<F>(mut self, f: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.teardown = Some(Box::new(f));
        self
    }

    pub fn run(&self, config: &BenchmarkConfig) -> SuiteResult {
        let start = Instant::now();
        let mut results = Vec::new();

        if let Some(ref setup) = self.setup {
            setup();
        }

        for bench in &self.benchmarks {
            if config.verbose {
                println!("Running benchmark: {}", bench.name());
            }

            // Warmup
            for _ in 0..config.warmup_iterations {
                bench.run();
            }

            // Actual benchmark
            let mut samples = Vec::with_capacity(config.iterations);
            for _ in 0..config.iterations {
                let iter_start = Instant::now();
                bench.run();
                samples.push(iter_start.elapsed());
            }

            let result = BenchmarkResult::new(bench.name(), samples);
            results.push(result);
        }

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

/// Trait for benchmark implementations
pub trait Benchmark: Send + Sync {
    fn name(&self) -> String;
    fn run(&self);
}

/// Simple function benchmark
pub struct FnBenchmark<F>
where
    F: Fn() + Send + Sync,
{
    name: String,
    func: F,
}

impl<F> FnBenchmark<F>
where
    F: Fn() + Send + Sync,
{
    pub fn new(name: impl Into<String>, func: F) -> Self {
        FnBenchmark {
            name: name.into(),
            func,
        }
    }
}

impl<F> Benchmark for FnBenchmark<F>
where
    F: Fn() + Send + Sync,
{
    fn name(&self) -> String {
        self.name.clone()
    }

    fn run(&self) {
        (self.func)();
    }
}

/// Result of running a benchmark suite
#[derive(Debug)]
pub struct SuiteResult {
    pub name: String,
    pub results: Vec<BenchmarkResult>,
    pub duration: Duration,
}

impl SuiteResult {
    /// Get result by name
    pub fn get(&self, name: &str) -> Option<&BenchmarkResult> {
        self.results.iter().find(|r| r.name == name)
    }

    /// Total benchmarks
    pub fn total(&self) -> usize {
        self.results.len()
    }
}

// ============ Benchmark Configuration ============

/// Configuration for benchmark runs
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Number of warmup iterations
    pub warmup_iterations: usize,
    /// Number of benchmark iterations
    pub iterations: usize,
    /// Timeout per benchmark
    pub timeout: Duration,
    /// Verbose output
    pub verbose: bool,
    /// Output format
    pub output_format: OutputFormat,
    /// Baseline comparison file
    pub baseline_file: Option<String>,
    /// Regression threshold (percentage)
    pub regression_threshold: f64,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        BenchmarkConfig {
            warmup_iterations: 10,
            iterations: 100,
            timeout: Duration::from_secs(60),
            verbose: false,
            output_format: OutputFormat::Pretty,
            baseline_file: None,
            regression_threshold: 10.0,
        }
    }
}

/// Output format for benchmark results
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Pretty,
    Json,
    Csv,
    Html,
    Markdown,
}

// ============ Benchmark Runner ============

/// Main benchmark runner
pub struct BenchmarkRunner {
    config: BenchmarkConfig,
    suites: Vec<BenchmarkSuite>,
}

impl BenchmarkRunner {
    pub fn new(config: BenchmarkConfig) -> Self {
        BenchmarkRunner {
            config,
            suites: Vec::new(),
        }
    }

    pub fn add_suite(mut self, suite: BenchmarkSuite) -> Self {
        self.suites.push(suite);
        self
    }

    pub fn run(&self) -> RunnerResult {
        let start = Instant::now();
        let mut suite_results = Vec::new();

        for suite in &self.suites {
            if self.config.verbose {
                println!("\n=== Running suite: {} ===\n", suite.name);
            }

            let result = suite.run(&self.config);
            suite_results.push(result);
        }

        RunnerResult {
            suites: suite_results,
            duration: start.elapsed(),
            config: self.config.clone(),
        }
    }
}

/// Result of running all benchmark suites
#[derive(Debug)]
pub struct RunnerResult {
    pub suites: Vec<SuiteResult>,
    pub duration: Duration,
    pub config: BenchmarkConfig,
}

impl RunnerResult {
    /// Total benchmarks across all suites
    pub fn total_benchmarks(&self) -> usize {
        self.suites.iter().map(|s| s.total()).sum()
    }

    /// Get all results flattened
    pub fn all_results(&self) -> Vec<&BenchmarkResult> {
        self.suites.iter().flat_map(|s| &s.results).collect()
    }

    /// Format as string based on output format
    pub fn format(&self) -> String {
        match self.config.output_format {
            OutputFormat::Pretty => self.format_pretty(),
            OutputFormat::Json => self.format_json(),
            OutputFormat::Csv => self.format_csv(),
            OutputFormat::Html => self.format_html(),
            OutputFormat::Markdown => self.format_markdown(),
        }
    }

    fn format_pretty(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("\n{}\n", "=".repeat(80)));
        output.push_str("Aethelred SDK Benchmark Results\n");
        output.push_str(&format!("{}\n\n", "=".repeat(80)));

        for suite in &self.suites {
            output.push_str(&format!("Suite: {}\n", suite.name));
            output.push_str(&format!("{}\n\n", "-".repeat(40)));

            for result in &suite.results {
                output.push_str(&format!(
                    "  {:<30} mean: {:>10.2?}  p50: {:>10.2?}  p95: {:>10.2?}  p99: {:>10.2?}\n",
                    result.name,
                    result.mean(),
                    result.p50(),
                    result.p95(),
                    result.p99()
                ));
            }

            output.push_str(&format!("\n  Suite duration: {:.2?}\n\n", suite.duration));
        }

        output.push_str(&format!("Total duration: {:.2?}\n", self.duration));

        output
    }

    fn format_json(&self) -> String {
        let mut data = serde_json::json!({
            "duration_ms": self.duration.as_millis(),
            "total_benchmarks": self.total_benchmarks(),
            "suites": []
        });

        if let serde_json::Value::Object(ref mut map) = data {
            let suites = map.get_mut("suites").unwrap();
            if let serde_json::Value::Array(ref mut arr) = suites {
                for suite in &self.suites {
                    let mut suite_data = serde_json::json!({
                        "name": suite.name,
                        "duration_ms": suite.duration.as_millis(),
                        "benchmarks": []
                    });

                    if let serde_json::Value::Object(ref mut suite_map) = suite_data {
                        let benchmarks = suite_map.get_mut("benchmarks").unwrap();
                        if let serde_json::Value::Array(ref mut bench_arr) = benchmarks {
                            for result in &suite.results {
                                bench_arr.push(serde_json::json!({
                                    "name": result.name,
                                    "iterations": result.iterations,
                                    "mean_ns": result.mean().as_nanos(),
                                    "median_ns": result.median().as_nanos(),
                                    "std_dev_ns": result.std_dev().as_nanos(),
                                    "min_ns": result.min().as_nanos(),
                                    "max_ns": result.max().as_nanos(),
                                    "p50_ns": result.p50().as_nanos(),
                                    "p95_ns": result.p95().as_nanos(),
                                    "p99_ns": result.p99().as_nanos(),
                                    "throughput": result.throughput()
                                }));
                            }
                        }
                    }

                    arr.push(suite_data);
                }
            }
        }

        serde_json::to_string_pretty(&data).unwrap_or_default()
    }

    fn format_csv(&self) -> String {
        let mut output = String::new();
        output.push_str("suite,name,iterations,mean_ns,median_ns,std_dev_ns,min_ns,max_ns,p50_ns,p95_ns,p99_ns,throughput\n");

        for suite in &self.suites {
            for result in &suite.results {
                output.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{:.2}\n",
                    suite.name,
                    result.name,
                    result.iterations,
                    result.mean().as_nanos(),
                    result.median().as_nanos(),
                    result.std_dev().as_nanos(),
                    result.min().as_nanos(),
                    result.max().as_nanos(),
                    result.p50().as_nanos(),
                    result.p95().as_nanos(),
                    result.p99().as_nanos(),
                    result.throughput()
                ));
            }
        }

        output
    }

    fn format_html(&self) -> String {
        let mut html = String::new();
        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("  <title>Benchmark Results</title>\n");
        html.push_str("  <style>\n");
        html.push_str(BENCHMARK_CSS);
        html.push_str("  </style>\n");
        html.push_str("</head>\n<body>\n");
        html.push_str("  <h1>Aethelred SDK Benchmark Results</h1>\n");

        for suite in &self.suites {
            html.push_str(&format!("  <h2>{}</h2>\n", suite.name));
            html.push_str("  <table>\n");
            html.push_str("    <tr><th>Benchmark</th><th>Mean</th><th>Median</th><th>P95</th><th>P99</th><th>Throughput</th></tr>\n");

            for result in &suite.results {
                html.push_str(&format!(
                    "    <tr><td>{}</td><td>{:.2?}</td><td>{:.2?}</td><td>{:.2?}</td><td>{:.2?}</td><td>{:.2}/s</td></tr>\n",
                    result.name,
                    result.mean(),
                    result.median(),
                    result.p95(),
                    result.p99(),
                    result.throughput()
                ));
            }

            html.push_str("  </table>\n");
        }

        html.push_str(&format!("  <p>Total duration: {:.2?}</p>\n", self.duration));
        html.push_str("</body>\n</html>\n");

        html
    }

    fn format_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# Aethelred SDK Benchmark Results\n\n");

        for suite in &self.suites {
            md.push_str(&format!("## {}\n\n", suite.name));
            md.push_str("| Benchmark | Mean | Median | P95 | P99 | Throughput |\n");
            md.push_str("|-----------|------|--------|-----|-----|------------|\n");

            for result in &suite.results {
                md.push_str(&format!(
                    "| {} | {:.2?} | {:.2?} | {:.2?} | {:.2?} | {:.2}/s |\n",
                    result.name,
                    result.mean(),
                    result.median(),
                    result.p95(),
                    result.p99(),
                    result.throughput()
                ));
            }

            md.push_str("\n");
        }

        md.push_str(&format!("\n**Total duration:** {:.2?}\n", self.duration));

        md
    }
}

const BENCHMARK_CSS: &str = r#"
    body { font-family: sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
    h1 { color: #333; }
    h2 { color: #555; border-bottom: 2px solid #eee; padding-bottom: 10px; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background: #f5f5f5; }
    tr:hover { background: #f9f9f9; }
"#;

// ============ Benchmark Macros ============

/// Create a simple benchmark
#[macro_export]
macro_rules! bench {
    ($name:expr, $body:expr) => {
        $crate::FnBenchmark::new($name, || {
            $body;
        })
    };
}

/// Create a benchmark suite
#[macro_export]
macro_rules! bench_suite {
    ($name:expr, $($bench:expr),* $(,)?) => {
        {
            let mut suite = $crate::BenchmarkSuite::new($name);
            $(
                suite = suite.add($bench);
            )*
            suite
        }
    };
}

// ============ Timing Utilities ============

/// Measure execution time of a function
pub fn measure<F, R>(f: F) -> (R, Duration)
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let result = f();
    (result, start.elapsed())
}

/// Measure with multiple iterations
pub fn measure_iterations<F, R>(iterations: usize, mut f: F) -> BenchmarkResult
where
    F: FnMut() -> R,
{
    let mut samples = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = f();
        samples.push(start.elapsed());
    }

    BenchmarkResult::new("measured", samples)
}

/// Black box to prevent compiler optimizations
#[inline(never)]
pub fn black_box<T>(x: T) -> T {
    // Use inline assembly or volatile read to prevent optimization
    std::hint::black_box(x)
}

// ============ Comparisons ============

/// Compare two benchmark results
#[derive(Debug)]
pub struct Comparison {
    pub name: String,
    pub baseline: BenchmarkResult,
    pub current: BenchmarkResult,
    pub change_percent: f64,
    pub is_regression: bool,
}

impl Comparison {
    pub fn new(
        name: &str,
        baseline: BenchmarkResult,
        current: BenchmarkResult,
        threshold: f64,
    ) -> Self {
        let baseline_mean = baseline.mean().as_nanos() as f64;
        let current_mean = current.mean().as_nanos() as f64;

        let change_percent = if baseline_mean > 0.0 {
            ((current_mean - baseline_mean) / baseline_mean) * 100.0
        } else {
            0.0
        };

        let is_regression = change_percent > threshold;

        Comparison {
            name: name.to_string(),
            baseline,
            current,
            change_percent,
            is_regression,
        }
    }
}

impl fmt::Display for Comparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let symbol = if self.change_percent > 5.0 {
            "🔴"
        } else if self.change_percent < -5.0 {
            "🟢"
        } else {
            "🟡"
        };

        write!(
            f,
            "{} {}: {:+.2}% ({:.2?} -> {:.2?})",
            symbol,
            self.name,
            self.change_percent,
            self.baseline.mean(),
            self.current.mean()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_result() {
        let samples = vec![
            Duration::from_millis(10),
            Duration::from_millis(12),
            Duration::from_millis(11),
            Duration::from_millis(15),
            Duration::from_millis(9),
        ];

        let result = BenchmarkResult::new("test", samples);

        assert_eq!(result.iterations, 5);
        assert!(result.mean() > Duration::from_millis(10));
        assert!(result.mean() < Duration::from_millis(12));
    }

    #[test]
    fn test_percentiles() {
        let samples: Vec<Duration> = (1..=100).map(|i| Duration::from_millis(i)).collect();

        let result = BenchmarkResult::new("test", samples);

        assert_eq!(result.p50().as_millis(), 50);
        assert_eq!(result.p95().as_millis(), 95);
        assert_eq!(result.p99().as_millis(), 99);
    }

    #[test]
    fn test_benchmark_suite() {
        let suite = BenchmarkSuite::new("test_suite")
            .add(FnBenchmark::new("noop", || {}))
            .add(FnBenchmark::new("sleep_1ms", || {
                std::thread::sleep(Duration::from_millis(1));
            }));

        let config = BenchmarkConfig {
            warmup_iterations: 2,
            iterations: 5,
            ..Default::default()
        };

        let result = suite.run(&config);
        assert_eq!(result.total(), 2);
    }
}
