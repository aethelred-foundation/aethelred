//! Performance Regression Detection Module
//!
//! Detect performance regressions by comparing benchmarks against
//! historical baselines with statistical analysis.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{BenchmarkResult, RunnerResult, SuiteResult};

// ============ Baseline Storage ============

/// Stores and retrieves benchmark baselines
pub struct BaselineStore {
    path: PathBuf,
    baselines: HashMap<String, Baseline>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Baseline {
    pub name: String,
    pub mean_ns: u64,
    pub std_dev_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub iterations: usize,
    pub timestamp: String,
    pub commit_hash: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl BaselineStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        let baselines = Self::load_from_file(&path).unwrap_or_default();

        BaselineStore { path, baselines }
    }

    fn load_from_file(path: &Path) -> Option<HashMap<String, Baseline>> {
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Save baselines to file
    pub fn save(&self) -> std::io::Result<()> {
        let content = serde_json::to_string_pretty(&self.baselines)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, content)
    }

    /// Get baseline for a benchmark
    pub fn get(&self, name: &str) -> Option<&Baseline> {
        self.baselines.get(name)
    }

    /// Update baseline from benchmark result
    pub fn update(&mut self, result: &BenchmarkResult) {
        let baseline = Baseline {
            name: result.name.clone(),
            mean_ns: result.mean().as_nanos() as u64,
            std_dev_ns: result.std_dev().as_nanos() as u64,
            p95_ns: result.p95().as_nanos() as u64,
            p99_ns: result.p99().as_nanos() as u64,
            iterations: result.iterations,
            timestamp: chrono::Utc::now().to_rfc3339(),
            commit_hash: Self::get_git_commit(),
            metadata: result.metadata.clone(),
        };

        self.baselines.insert(result.name.clone(), baseline);
    }

    /// Update all baselines from runner result
    pub fn update_all(&mut self, result: &RunnerResult) {
        for suite in &result.suites {
            for bench in &suite.results {
                self.update(bench);
            }
        }
    }

    fn get_git_commit() -> Option<String> {
        std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
                } else {
                    None
                }
            })
    }
}

// ============ Regression Detection ============

/// Configuration for regression detection
#[derive(Debug, Clone)]
pub struct RegressionConfig {
    /// Threshold for flagging regression (percentage)
    pub threshold_percent: f64,
    /// Minimum number of samples for statistical significance
    pub min_samples: usize,
    /// Use statistical tests
    pub statistical_tests: bool,
    /// Confidence level for statistical tests
    pub confidence_level: f64,
    /// Ignore benchmarks matching patterns
    pub ignore_patterns: Vec<String>,
}

impl Default for RegressionConfig {
    fn default() -> Self {
        RegressionConfig {
            threshold_percent: 10.0,
            min_samples: 10,
            statistical_tests: true,
            confidence_level: 0.95,
            ignore_patterns: Vec::new(),
        }
    }
}

/// Regression detection result
#[derive(Debug, Clone)]
pub struct RegressionResult {
    pub benchmark_name: String,
    pub baseline: Baseline,
    pub current: BenchmarkMetrics,
    pub change_percent: f64,
    pub is_regression: bool,
    pub is_improvement: bool,
    pub statistical_significance: Option<f64>,
    pub recommendation: String,
}

#[derive(Debug, Clone)]
pub struct BenchmarkMetrics {
    pub mean_ns: u64,
    pub std_dev_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub iterations: usize,
}

impl From<&BenchmarkResult> for BenchmarkMetrics {
    fn from(result: &BenchmarkResult) -> Self {
        BenchmarkMetrics {
            mean_ns: result.mean().as_nanos() as u64,
            std_dev_ns: result.std_dev().as_nanos() as u64,
            p95_ns: result.p95().as_nanos() as u64,
            p99_ns: result.p99().as_nanos() as u64,
            iterations: result.iterations,
        }
    }
}

/// Regression detector
pub struct RegressionDetector {
    config: RegressionConfig,
    baseline_store: BaselineStore,
}

impl RegressionDetector {
    pub fn new(config: RegressionConfig, baseline_store: BaselineStore) -> Self {
        RegressionDetector {
            config,
            baseline_store,
        }
    }

    /// Analyze a benchmark result for regression
    pub fn analyze(&self, result: &BenchmarkResult) -> Option<RegressionResult> {
        // Check ignore patterns
        for pattern in &self.config.ignore_patterns {
            if result.name.contains(pattern) {
                return None;
            }
        }

        let baseline = self.baseline_store.get(&result.name)?;
        let current = BenchmarkMetrics::from(result);

        let change_percent = if baseline.mean_ns > 0 {
            ((current.mean_ns as f64 - baseline.mean_ns as f64) / baseline.mean_ns as f64) * 100.0
        } else {
            0.0
        };

        let is_regression = change_percent > self.config.threshold_percent;
        let is_improvement = change_percent < -self.config.threshold_percent;

        let statistical_significance = if self.config.statistical_tests {
            Some(self.calculate_significance(baseline, &current))
        } else {
            None
        };

        let recommendation = self.generate_recommendation(
            change_percent,
            is_regression,
            is_improvement,
            statistical_significance,
        );

        Some(RegressionResult {
            benchmark_name: result.name.clone(),
            baseline: baseline.clone(),
            current,
            change_percent,
            is_regression,
            is_improvement,
            statistical_significance,
            recommendation,
        })
    }

    /// Analyze all results from a runner
    pub fn analyze_all(&self, runner_result: &RunnerResult) -> Vec<RegressionResult> {
        runner_result
            .all_results()
            .into_iter()
            .filter_map(|r| self.analyze(r))
            .collect()
    }

    /// Calculate statistical significance using Welch's t-test approximation
    fn calculate_significance(&self, baseline: &Baseline, current: &BenchmarkMetrics) -> f64 {
        let n1 = baseline.iterations as f64;
        let n2 = current.iterations as f64;

        let mean1 = baseline.mean_ns as f64;
        let mean2 = current.mean_ns as f64;

        let var1 = (baseline.std_dev_ns as f64).powi(2);
        let var2 = (current.std_dev_ns as f64).powi(2);

        // Welch's t-statistic
        let se = ((var1 / n1) + (var2 / n2)).sqrt();
        if se == 0.0 {
            return 0.0;
        }

        let t = (mean2 - mean1) / se;

        // Approximate p-value using normal distribution
        // (proper implementation would use t-distribution)
        let p_value = 2.0 * (1.0 - Self::normal_cdf(t.abs()));

        1.0 - p_value
    }

    fn normal_cdf(x: f64) -> f64 {
        0.5 * (1.0 + Self::erf(x / std::f64::consts::SQRT_2))
    }

    fn erf(x: f64) -> f64 {
        // Approximation of error function
        let a1 = 0.254829592;
        let a2 = -0.284496736;
        let a3 = 1.421413741;
        let a4 = -1.453152027;
        let a5 = 1.061405429;
        let p = 0.3275911;

        let sign = if x < 0.0 { -1.0 } else { 1.0 };
        let x = x.abs();

        let t = 1.0 / (1.0 + p * x);
        let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-x * x).exp();

        sign * y
    }

    fn generate_recommendation(
        &self,
        change_percent: f64,
        is_regression: bool,
        is_improvement: bool,
        significance: Option<f64>,
    ) -> String {
        let significant = significance
            .map(|s| s >= self.config.confidence_level)
            .unwrap_or(false);

        if is_regression && significant {
            format!(
                "⚠️ REGRESSION DETECTED: {:.1}% slower. Investigate recent changes.",
                change_percent
            )
        } else if is_regression && !significant {
            format!(
                "⚡ Possible regression ({:.1}% slower) but not statistically significant.",
                change_percent
            )
        } else if is_improvement && significant {
            format!(
                "✅ IMPROVEMENT: {:.1}% faster! Consider updating baseline.",
                -change_percent
            )
        } else if is_improvement && !significant {
            format!(
                "📈 Possible improvement ({:.1}% faster) but not statistically significant.",
                -change_percent
            )
        } else {
            format!(
                "✓ Performance stable ({:+.1}% change within threshold).",
                change_percent
            )
        }
    }
}

// ============ Regression Report ============

/// Generate regression reports
pub struct RegressionReport {
    results: Vec<RegressionResult>,
}

impl RegressionReport {
    pub fn new(results: Vec<RegressionResult>) -> Self {
        RegressionReport { results }
    }

    /// Check if any regressions detected
    pub fn has_regressions(&self) -> bool {
        self.results.iter().any(|r| r.is_regression)
    }

    /// Get all regressions
    pub fn regressions(&self) -> Vec<&RegressionResult> {
        self.results.iter().filter(|r| r.is_regression).collect()
    }

    /// Get all improvements
    pub fn improvements(&self) -> Vec<&RegressionResult> {
        self.results.iter().filter(|r| r.is_improvement).collect()
    }

    /// Generate text report
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str("Performance Regression Report\n");
        s.push_str(&format!("{}\n\n", "=".repeat(50)));

        let regressions = self.regressions();
        let improvements = self.improvements();

        let num_regressions = regressions.len();
        let num_improvements = improvements.len();

        if regressions.is_empty() && improvements.is_empty() {
            s.push_str("No significant performance changes detected.\n\n");
        }

        if !regressions.is_empty() {
            s.push_str(&format!("{} Regressions Detected:\n", num_regressions));
            s.push_str(&format!("{}\n", "-".repeat(40)));

            for result in regressions {
                s.push_str(&format!(
                    "  {} [{:+.1}%]\n",
                    result.benchmark_name, result.change_percent
                ));
                s.push_str(&format!(
                    "    Baseline: {:.2?} -> Current: {:.2?}\n",
                    Duration::from_nanos(result.baseline.mean_ns),
                    Duration::from_nanos(result.current.mean_ns)
                ));
                s.push_str(&format!("    {}\n\n", result.recommendation));
            }
        }

        if !improvements.is_empty() {
            s.push_str(&format!("\n{} Improvements:\n", num_improvements));
            s.push_str(&format!("{}\n", "-".repeat(40)));

            for result in improvements {
                s.push_str(&format!(
                    "  {} [{:+.1}%]\n",
                    result.benchmark_name, result.change_percent
                ));
            }
        }

        // Summary
        s.push_str(&format!("\nSummary:\n"));
        s.push_str(&format!("  Total benchmarks: {}\n", self.results.len()));
        s.push_str(&format!("  Regressions: {}\n", num_regressions));
        s.push_str(&format!("  Improvements: {}\n", num_improvements));
        s.push_str(&format!(
            "  Stable: {}\n",
            self.results.len() - num_regressions - num_improvements
        ));

        s
    }

    /// Generate JSON report
    pub fn to_json(&self) -> String {
        let data = serde_json::json!({
            "summary": {
                "total": self.results.len(),
                "regressions": self.regressions().len(),
                "improvements": self.improvements().len(),
            },
            "results": self.results.iter().map(|r| {
                serde_json::json!({
                    "name": r.benchmark_name,
                    "change_percent": r.change_percent,
                    "is_regression": r.is_regression,
                    "is_improvement": r.is_improvement,
                    "baseline_ns": r.baseline.mean_ns,
                    "current_ns": r.current.mean_ns,
                    "statistical_significance": r.statistical_significance,
                    "recommendation": r.recommendation,
                })
            }).collect::<Vec<_>>(),
        });

        serde_json::to_string_pretty(&data).unwrap_or_default()
    }

    /// Generate markdown report (for CI/CD)
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# Performance Regression Report\n\n");

        let regressions = self.regressions();
        let improvements = self.improvements();

        if self.has_regressions() {
            md.push_str("## ⚠️ Regressions Detected\n\n");
            md.push_str("| Benchmark | Change | Baseline | Current |\n");
            md.push_str("|-----------|--------|----------|--------|\n");

            for result in &regressions {
                md.push_str(&format!(
                    "| {} | {:+.1}% | {:.2?} | {:.2?} |\n",
                    result.benchmark_name,
                    result.change_percent,
                    Duration::from_nanos(result.baseline.mean_ns),
                    Duration::from_nanos(result.current.mean_ns)
                ));
            }
            md.push_str("\n");
        }

        if !improvements.is_empty() {
            md.push_str("## ✅ Improvements\n\n");
            md.push_str("| Benchmark | Change |\n");
            md.push_str("|-----------|--------|\n");

            for result in &improvements {
                md.push_str(&format!(
                    "| {} | {:+.1}% |\n",
                    result.benchmark_name, result.change_percent
                ));
            }
            md.push_str("\n");
        }

        if regressions.is_empty() && improvements.is_empty() {
            md.push_str("✅ No significant performance changes detected.\n\n");
        }

        md.push_str("## Summary\n\n");
        md.push_str(&format!("- **Total benchmarks:** {}\n", self.results.len()));
        md.push_str(&format!("- **Regressions:** {}\n", regressions.len()));
        md.push_str(&format!("- **Improvements:** {}\n", improvements.len()));

        md
    }
}

// ============ CI/CD Integration ============

/// Exit code for CI/CD based on regression detection
pub fn get_exit_code(report: &RegressionReport) -> i32 {
    if report.has_regressions() {
        1 // Fail build on regression
    } else {
        0 // Success
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regression_detection() {
        // Create baseline
        let mut store = BaselineStore::new("/tmp/test_baselines.json");

        let baseline_result = BenchmarkResult::new(
            "test_benchmark",
            vec![
                Duration::from_millis(100),
                Duration::from_millis(105),
                Duration::from_millis(95),
            ],
        );
        store.update(&baseline_result);

        // Create current result with regression
        let current_result = BenchmarkResult::new(
            "test_benchmark",
            vec![
                Duration::from_millis(120),
                Duration::from_millis(125),
                Duration::from_millis(115),
            ],
        );

        let config = RegressionConfig::default();
        let detector = RegressionDetector::new(config, store);

        let result = detector.analyze(&current_result).unwrap();
        assert!(result.is_regression);
        assert!(result.change_percent > 0.0);
    }
}
