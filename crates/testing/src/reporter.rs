//! Aethelred SDK Test Reporters
//!
//! Multiple output formats for test results including
//! JUnit XML, TAP, JSON, HTML, and custom reporters.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use crate::{RunResult, SuiteResult, TestResult};

// ============ Reporter Trait ============

/// Trait for test result reporters
pub trait Reporter: Send + Sync {
    /// Called before any tests run
    fn on_run_start(&mut self, total_suites: usize, total_tests: usize);

    /// Called when a suite starts
    fn on_suite_start(&mut self, name: &str, test_count: usize);

    /// Called when a test completes
    fn on_test_complete(&mut self, suite_name: &str, test_name: &str, result: &TestResult);

    /// Called when a suite completes
    fn on_suite_complete(&mut self, result: &SuiteResult);

    /// Called after all tests complete
    fn on_run_complete(&mut self, result: &RunResult);

    /// Generate final output
    fn generate(&self) -> String;

    /// Write output to file
    fn write_to_file(&self, path: &Path) -> std::io::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(self.generate().as_bytes())?;
        Ok(())
    }
}

// ============ JUnit XML Reporter ============

/// Generates JUnit-compatible XML reports
pub struct JUnitReporter {
    suites: Vec<JUnitSuite>,
    current_suite: Option<JUnitSuite>,
}

struct JUnitSuite {
    name: String,
    tests: Vec<JUnitTest>,
    duration: Duration,
}

struct JUnitTest {
    name: String,
    classname: String,
    duration: Duration,
    status: JUnitStatus,
}

enum JUnitStatus {
    Passed,
    Failed {
        message: String,
        stack_trace: Option<String>,
    },
    Skipped {
        message: String,
    },
    Error {
        message: String,
    },
}

impl JUnitReporter {
    pub fn new() -> Self {
        JUnitReporter {
            suites: Vec::new(),
            current_suite: None,
        }
    }
}

impl Default for JUnitReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for JUnitReporter {
    fn on_run_start(&mut self, _total_suites: usize, _total_tests: usize) {
        self.suites.clear();
    }

    fn on_suite_start(&mut self, name: &str, _test_count: usize) {
        self.current_suite = Some(JUnitSuite {
            name: name.to_string(),
            tests: Vec::new(),
            duration: Duration::ZERO,
        });
    }

    fn on_test_complete(&mut self, suite_name: &str, test_name: &str, result: &TestResult) {
        if let Some(ref mut suite) = self.current_suite {
            let status = match result {
                TestResult::Passed { .. } => JUnitStatus::Passed,
                TestResult::Failed {
                    message, location, ..
                } => JUnitStatus::Failed {
                    message: message.clone(),
                    stack_trace: location.clone(),
                },
                TestResult::Skipped { reason } => JUnitStatus::Skipped {
                    message: reason.clone(),
                },
                TestResult::TimedOut { timeout } => JUnitStatus::Error {
                    message: format!("Test timed out after {:?}", timeout),
                },
            };

            let duration = match result {
                TestResult::Passed { duration } => *duration,
                TestResult::Failed { duration, .. } => *duration,
                TestResult::Skipped { .. } => Duration::ZERO,
                TestResult::TimedOut { timeout } => *timeout,
            };

            suite.tests.push(JUnitTest {
                name: test_name.to_string(),
                classname: suite_name.to_string(),
                duration,
                status,
            });
        }
    }

    fn on_suite_complete(&mut self, result: &SuiteResult) {
        if let Some(mut suite) = self.current_suite.take() {
            suite.duration = result.duration;
            self.suites.push(suite);
        }
    }

    fn on_run_complete(&mut self, _result: &RunResult) {}

    fn generate(&self) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<testsuites>\n");

        for suite in &self.suites {
            let tests = suite.tests.len();
            let failures = suite
                .tests
                .iter()
                .filter(|t| matches!(t.status, JUnitStatus::Failed { .. }))
                .count();
            let errors = suite
                .tests
                .iter()
                .filter(|t| matches!(t.status, JUnitStatus::Error { .. }))
                .count();
            let skipped = suite
                .tests
                .iter()
                .filter(|t| matches!(t.status, JUnitStatus::Skipped { .. }))
                .count();

            xml.push_str(&format!(
                "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"{}\" skipped=\"{}\" time=\"{:.3}\">\n",
                escape_xml(&suite.name),
                tests,
                failures,
                errors,
                skipped,
                suite.duration.as_secs_f64()
            ));

            for test in &suite.tests {
                xml.push_str(&format!(
                    "    <testcase name=\"{}\" classname=\"{}\" time=\"{:.3}\"",
                    escape_xml(&test.name),
                    escape_xml(&test.classname),
                    test.duration.as_secs_f64()
                ));

                match &test.status {
                    JUnitStatus::Passed => {
                        xml.push_str(" />\n");
                    }
                    JUnitStatus::Failed {
                        message,
                        stack_trace,
                    } => {
                        xml.push_str(">\n");
                        xml.push_str(&format!(
                            "      <failure message=\"{}\">{}</failure>\n",
                            escape_xml(message),
                            stack_trace
                                .as_ref()
                                .map(|s| escape_xml(s))
                                .unwrap_or_default()
                        ));
                        xml.push_str("    </testcase>\n");
                    }
                    JUnitStatus::Skipped { message } => {
                        xml.push_str(">\n");
                        xml.push_str(&format!(
                            "      <skipped message=\"{}\" />\n",
                            escape_xml(message)
                        ));
                        xml.push_str("    </testcase>\n");
                    }
                    JUnitStatus::Error { message } => {
                        xml.push_str(">\n");
                        xml.push_str(&format!(
                            "      <error message=\"{}\" />\n",
                            escape_xml(message)
                        ));
                        xml.push_str("    </testcase>\n");
                    }
                }
            }

            xml.push_str("  </testsuite>\n");
        }

        xml.push_str("</testsuites>\n");
        xml
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ============ TAP Reporter ============

/// Generates TAP (Test Anything Protocol) reports
pub struct TapReporter {
    lines: Vec<String>,
    test_number: usize,
}

impl TapReporter {
    pub fn new() -> Self {
        TapReporter {
            lines: Vec::new(),
            test_number: 0,
        }
    }
}

impl Default for TapReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for TapReporter {
    fn on_run_start(&mut self, _total_suites: usize, total_tests: usize) {
        self.lines.clear();
        self.test_number = 0;
        self.lines.push(format!("TAP version 14"));
        self.lines.push(format!("1..{}", total_tests));
    }

    fn on_suite_start(&mut self, name: &str, _test_count: usize) {
        self.lines.push(format!("# Suite: {}", name));
    }

    fn on_test_complete(&mut self, _suite_name: &str, test_name: &str, result: &TestResult) {
        self.test_number += 1;

        let line = match result {
            TestResult::Passed { duration } => {
                format!("ok {} - {} ({:.2?})", self.test_number, test_name, duration)
            }
            TestResult::Failed {
                message, duration, ..
            } => {
                let mut line = format!(
                    "not ok {} - {} ({:.2?})",
                    self.test_number, test_name, duration
                );
                line.push_str(&format!("\n  ---\n  message: {}\n  ...", message));
                line
            }
            TestResult::Skipped { reason } => {
                format!("ok {} - {} # SKIP {}", self.test_number, test_name, reason)
            }
            TestResult::TimedOut { timeout } => {
                format!(
                    "not ok {} - {} # TIMEOUT ({:?})",
                    self.test_number, test_name, timeout
                )
            }
        };

        self.lines.push(line);
    }

    fn on_suite_complete(&mut self, _result: &SuiteResult) {}

    fn on_run_complete(&mut self, result: &RunResult) {
        self.lines.push(format!(
            "# {} tests, {} passed, {} failed",
            result.total_tests(),
            result.total_passed(),
            result.total_failed()
        ));
    }

    fn generate(&self) -> String {
        self.lines.join("\n")
    }
}

// ============ JSON Reporter ============

/// Generates JSON reports
pub struct JsonReporter {
    data: JsonReport,
}

#[derive(Debug, Clone, serde::Serialize)]
struct JsonReport {
    version: String,
    timestamp: String,
    duration_ms: u64,
    stats: JsonStats,
    suites: Vec<JsonSuite>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct JsonStats {
    total: usize,
    passed: usize,
    failed: usize,
    skipped: usize,
    timed_out: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
struct JsonSuite {
    name: String,
    duration_ms: u64,
    tests: Vec<JsonTest>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct JsonTest {
    name: String,
    status: String,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
}

impl JsonReporter {
    pub fn new() -> Self {
        JsonReporter {
            data: JsonReport {
                version: "1.0".to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                duration_ms: 0,
                stats: JsonStats {
                    total: 0,
                    passed: 0,
                    failed: 0,
                    skipped: 0,
                    timed_out: 0,
                },
                suites: Vec::new(),
            },
        }
    }
}

impl Default for JsonReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for JsonReporter {
    fn on_run_start(&mut self, _total_suites: usize, _total_tests: usize) {
        self.data.suites.clear();
        self.data.timestamp = chrono::Utc::now().to_rfc3339();
    }

    fn on_suite_start(&mut self, name: &str, _test_count: usize) {
        self.data.suites.push(JsonSuite {
            name: name.to_string(),
            duration_ms: 0,
            tests: Vec::new(),
        });
    }

    fn on_test_complete(&mut self, _suite_name: &str, test_name: &str, result: &TestResult) {
        if let Some(suite) = self.data.suites.last_mut() {
            let (status, duration_ms, message, location) = match result {
                TestResult::Passed { duration } => (
                    "passed".to_string(),
                    duration.as_millis() as u64,
                    None,
                    None,
                ),
                TestResult::Failed {
                    message,
                    location,
                    duration,
                } => (
                    "failed".to_string(),
                    duration.as_millis() as u64,
                    Some(message.clone()),
                    location.clone(),
                ),
                TestResult::Skipped { reason } => {
                    ("skipped".to_string(), 0, Some(reason.clone()), None)
                }
                TestResult::TimedOut { timeout } => (
                    "timed_out".to_string(),
                    timeout.as_millis() as u64,
                    None,
                    None,
                ),
            };

            suite.tests.push(JsonTest {
                name: test_name.to_string(),
                status,
                duration_ms,
                message,
                location,
            });
        }
    }

    fn on_suite_complete(&mut self, result: &SuiteResult) {
        if let Some(suite) = self.data.suites.last_mut() {
            suite.duration_ms = result.duration.as_millis() as u64;
        }
    }

    fn on_run_complete(&mut self, result: &RunResult) {
        self.data.duration_ms = result.duration.as_millis() as u64;
        self.data.stats = JsonStats {
            total: result.total_tests(),
            passed: result.total_passed(),
            failed: result.total_failed(),
            skipped: result.total_skipped(),
            timed_out: 0, // Would need to track separately
        };
    }

    fn generate(&self) -> String {
        serde_json::to_string_pretty(&self.data).unwrap_or_default()
    }
}

// ============ HTML Reporter ============

/// Generates HTML reports with styling
pub struct HtmlReporter {
    data: HtmlReportData,
}

struct HtmlReportData {
    title: String,
    suites: Vec<HtmlSuite>,
    stats: HtmlStats,
    duration: Duration,
}

struct HtmlSuite {
    name: String,
    tests: Vec<HtmlTest>,
    passed: usize,
    failed: usize,
    skipped: usize,
    duration: Duration,
}

struct HtmlTest {
    name: String,
    status: String,
    status_class: String,
    duration: Duration,
    message: Option<String>,
}

struct HtmlStats {
    total: usize,
    passed: usize,
    failed: usize,
    skipped: usize,
}

impl HtmlReporter {
    pub fn new(title: &str) -> Self {
        HtmlReporter {
            data: HtmlReportData {
                title: title.to_string(),
                suites: Vec::new(),
                stats: HtmlStats {
                    total: 0,
                    passed: 0,
                    failed: 0,
                    skipped: 0,
                },
                duration: Duration::ZERO,
            },
        }
    }
}

impl Reporter for HtmlReporter {
    fn on_run_start(&mut self, _total_suites: usize, _total_tests: usize) {
        self.data.suites.clear();
    }

    fn on_suite_start(&mut self, name: &str, _test_count: usize) {
        self.data.suites.push(HtmlSuite {
            name: name.to_string(),
            tests: Vec::new(),
            passed: 0,
            failed: 0,
            skipped: 0,
            duration: Duration::ZERO,
        });
    }

    fn on_test_complete(&mut self, _suite_name: &str, test_name: &str, result: &TestResult) {
        if let Some(suite) = self.data.suites.last_mut() {
            let (status, status_class, duration, message) = match result {
                TestResult::Passed { duration } => {
                    suite.passed += 1;
                    ("Passed".to_string(), "passed".to_string(), *duration, None)
                }
                TestResult::Failed {
                    message, duration, ..
                } => {
                    suite.failed += 1;
                    (
                        "Failed".to_string(),
                        "failed".to_string(),
                        *duration,
                        Some(message.clone()),
                    )
                }
                TestResult::Skipped { reason } => {
                    suite.skipped += 1;
                    (
                        "Skipped".to_string(),
                        "skipped".to_string(),
                        Duration::ZERO,
                        Some(reason.clone()),
                    )
                }
                TestResult::TimedOut { timeout } => {
                    suite.failed += 1;
                    (
                        "Timed Out".to_string(),
                        "failed".to_string(),
                        *timeout,
                        None,
                    )
                }
            };

            suite.tests.push(HtmlTest {
                name: test_name.to_string(),
                status,
                status_class,
                duration,
                message,
            });
        }
    }

    fn on_suite_complete(&mut self, result: &SuiteResult) {
        if let Some(suite) = self.data.suites.last_mut() {
            suite.duration = result.duration;
        }
    }

    fn on_run_complete(&mut self, result: &RunResult) {
        self.data.duration = result.duration;
        self.data.stats = HtmlStats {
            total: result.total_tests(),
            passed: result.total_passed(),
            failed: result.total_failed(),
            skipped: result.total_skipped(),
        };
    }

    fn generate(&self) -> String {
        let mut html = String::new();

        html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("  <meta charset=\"UTF-8\">\n");
        html.push_str(
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n",
        );
        html.push_str(&format!(
            "  <title>{}</title>\n",
            escape_html(&self.data.title)
        ));
        html.push_str("  <style>\n");
        html.push_str(CSS_STYLES);
        html.push_str("  </style>\n");
        html.push_str("</head>\n<body>\n");

        // Header
        html.push_str(&format!("  <h1>{}</h1>\n", escape_html(&self.data.title)));

        // Stats
        let success_rate = if self.data.stats.total > 0 {
            (self.data.stats.passed as f64 / self.data.stats.total as f64 * 100.0) as u32
        } else {
            100
        };

        html.push_str("  <div class=\"stats\">\n");
        html.push_str(&format!(
            "    <div class=\"stat\"><span class=\"label\">Total:</span> {}</div>\n",
            self.data.stats.total
        ));
        html.push_str(&format!(
            "    <div class=\"stat passed\"><span class=\"label\">Passed:</span> {}</div>\n",
            self.data.stats.passed
        ));
        html.push_str(&format!(
            "    <div class=\"stat failed\"><span class=\"label\">Failed:</span> {}</div>\n",
            self.data.stats.failed
        ));
        html.push_str(&format!(
            "    <div class=\"stat skipped\"><span class=\"label\">Skipped:</span> {}</div>\n",
            self.data.stats.skipped
        ));
        html.push_str(&format!(
            "    <div class=\"stat\"><span class=\"label\">Duration:</span> {:.2?}</div>\n",
            self.data.duration
        ));
        html.push_str(&format!(
            "    <div class=\"stat\"><span class=\"label\">Success Rate:</span> {}%</div>\n",
            success_rate
        ));
        html.push_str("  </div>\n");

        // Progress bar
        html.push_str(&format!(
            "  <div class=\"progress\"><div class=\"bar\" style=\"width: {}%\"></div></div>\n",
            success_rate
        ));

        // Suites
        for suite in &self.data.suites {
            html.push_str("  <div class=\"suite\">\n");
            html.push_str(&format!(
                "    <h2>{} <small>({} passed, {} failed, {} skipped - {:.2?})</small></h2>\n",
                escape_html(&suite.name),
                suite.passed,
                suite.failed,
                suite.skipped,
                suite.duration
            ));
            html.push_str("    <table>\n");
            html.push_str(
                "      <tr><th>Test</th><th>Status</th><th>Duration</th><th>Message</th></tr>\n",
            );

            for test in &suite.tests {
                html.push_str(&format!(
                    "      <tr class=\"{}\"><td>{}</td><td>{}</td><td>{:.2?}</td><td>{}</td></tr>\n",
                    test.status_class,
                    escape_html(&test.name),
                    test.status,
                    test.duration,
                    test.message.as_ref().map(|m| escape_html(m)).unwrap_or_default()
                ));
            }

            html.push_str("    </table>\n");
            html.push_str("  </div>\n");
        }

        html.push_str("</body>\n</html>\n");
        html
    }
}

const CSS_STYLES: &str = r#"
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
      background: #f5f5f5;
    }
    h1 { color: #333; }
    h2 { color: #555; font-size: 1.2em; }
    h2 small { color: #888; font-weight: normal; }
    .stats {
      display: flex;
      gap: 20px;
      margin: 20px 0;
      flex-wrap: wrap;
    }
    .stat {
      background: white;
      padding: 10px 20px;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .stat.passed { border-left: 4px solid #4caf50; }
    .stat.failed { border-left: 4px solid #f44336; }
    .stat.skipped { border-left: 4px solid #ff9800; }
    .label { color: #666; margin-right: 5px; }
    .progress {
      height: 8px;
      background: #f44336;
      border-radius: 4px;
      overflow: hidden;
      margin: 20px 0;
    }
    .bar {
      height: 100%;
      background: #4caf50;
      transition: width 0.3s;
    }
    .suite {
      background: white;
      padding: 20px;
      margin: 20px 0;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      text-align: left;
      padding: 10px;
      border-bottom: 1px solid #eee;
    }
    th { background: #f9f9f9; }
    tr.passed td:nth-child(2) { color: #4caf50; }
    tr.failed td:nth-child(2) { color: #f44336; }
    tr.skipped td:nth-child(2) { color: #ff9800; }
"#;

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ============ Multi Reporter ============

/// Combines multiple reporters
pub struct MultiReporter {
    reporters: Vec<Box<dyn Reporter>>,
}

impl MultiReporter {
    pub fn new() -> Self {
        MultiReporter {
            reporters: Vec::new(),
        }
    }

    pub fn add<R: Reporter + 'static>(mut self, reporter: R) -> Self {
        self.reporters.push(Box::new(reporter));
        self
    }
}

impl Default for MultiReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for MultiReporter {
    fn on_run_start(&mut self, total_suites: usize, total_tests: usize) {
        for r in &mut self.reporters {
            r.on_run_start(total_suites, total_tests);
        }
    }

    fn on_suite_start(&mut self, name: &str, test_count: usize) {
        for r in &mut self.reporters {
            r.on_suite_start(name, test_count);
        }
    }

    fn on_test_complete(&mut self, suite_name: &str, test_name: &str, result: &TestResult) {
        for r in &mut self.reporters {
            r.on_test_complete(suite_name, test_name, result);
        }
    }

    fn on_suite_complete(&mut self, result: &SuiteResult) {
        for r in &mut self.reporters {
            r.on_suite_complete(result);
        }
    }

    fn on_run_complete(&mut self, result: &RunResult) {
        for r in &mut self.reporters {
            r.on_run_complete(result);
        }
    }

    fn generate(&self) -> String {
        // Return first reporter's output
        self.reporters
            .first()
            .map(|r| r.generate())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_junit_reporter() {
        let mut reporter = JUnitReporter::new();
        reporter.on_run_start(1, 2);
        reporter.on_suite_start("TestSuite", 2);
        reporter.on_test_complete(
            "TestSuite",
            "test1",
            &TestResult::Passed {
                duration: Duration::from_millis(100),
            },
        );
        reporter.on_test_complete(
            "TestSuite",
            "test2",
            &TestResult::Failed {
                message: "Expected true".to_string(),
                location: None,
                duration: Duration::from_millis(50),
            },
        );

        let xml = reporter.generate();
        assert!(xml.contains("<testsuite"));
        assert!(xml.contains("test1"));
        assert!(xml.contains("test2"));
        assert!(xml.contains("<failure"));
    }

    #[test]
    fn test_tap_reporter() {
        let mut reporter = TapReporter::new();
        reporter.on_run_start(1, 2);
        reporter.on_test_complete(
            "Suite",
            "test1",
            &TestResult::Passed {
                duration: Duration::from_millis(100),
            },
        );

        let output = reporter.generate();
        assert!(output.contains("TAP version"));
        assert!(output.contains("ok 1"));
    }

    #[test]
    fn test_json_reporter() {
        let mut reporter = JsonReporter::new();
        reporter.on_run_start(1, 1);
        reporter.on_suite_start("Suite", 1);
        reporter.on_test_complete(
            "Suite",
            "test1",
            &TestResult::Passed {
                duration: Duration::from_millis(100),
            },
        );

        let json = reporter.generate();
        assert!(json.contains("\"passed\""));
    }
}
