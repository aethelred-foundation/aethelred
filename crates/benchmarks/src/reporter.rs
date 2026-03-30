//! Benchmark Report Generation Module
//!
//! Generate comprehensive benchmark reports in multiple formats
//! including HTML dashboards, JSON, CSV, and markdown.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::{RunnerResult, SuiteResult};

// ============ Report Configuration ============

/// Configuration for report generation
#[derive(Debug, Clone)]
pub struct ReportConfig {
    /// Title for the report
    pub title: String,
    /// Include charts (for HTML)
    pub include_charts: bool,
    /// Include raw data
    pub include_raw_data: bool,
    /// Include historical comparison
    pub include_history: bool,
    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        ReportConfig {
            title: "Aethelred SDK Benchmark Report".to_string(),
            include_charts: true,
            include_raw_data: false,
            include_history: false,
            metadata: HashMap::new(),
        }
    }
}

// ============ Report Generator ============

/// Generate benchmark reports
pub struct ReportGenerator {
    config: ReportConfig,
}

impl ReportGenerator {
    pub fn new(config: ReportConfig) -> Self {
        ReportGenerator { config }
    }

    /// Generate HTML report with interactive charts
    pub fn generate_html(&self, result: &RunnerResult) -> String {
        let mut html = String::new();

        html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("  <meta charset=\"UTF-8\">\n");
        html.push_str(
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n",
        );
        html.push_str(&format!("  <title>{}</title>\n", self.config.title));
        html.push_str("  <style>\n");
        html.push_str(REPORT_CSS);
        html.push_str("  </style>\n");

        if self.config.include_charts {
            html.push_str("  <script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>\n");
        }

        html.push_str("</head>\n<body>\n");

        // Header
        html.push_str("  <header>\n");
        html.push_str(&format!("    <h1>{}</h1>\n", self.config.title));
        html.push_str(&format!(
            "    <p class=\"timestamp\">Generated: {}</p>\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));
        html.push_str("  </header>\n");

        // Summary section
        html.push_str("  <section class=\"summary\">\n");
        html.push_str("    <h2>Summary</h2>\n");
        html.push_str("    <div class=\"stats-grid\">\n");
        html.push_str(&format!(
            "      <div class=\"stat\"><span class=\"value\">{}</span><span class=\"label\">Total Benchmarks</span></div>\n",
            result.total_benchmarks()
        ));
        html.push_str(&format!(
            "      <div class=\"stat\"><span class=\"value\">{}</span><span class=\"label\">Suites</span></div>\n",
            result.suites.len()
        ));
        html.push_str(&format!(
            "      <div class=\"stat\"><span class=\"value\">{:.2?}</span><span class=\"label\">Total Duration</span></div>\n",
            result.duration
        ));
        html.push_str("    </div>\n");
        html.push_str("  </section>\n");

        // Per-suite results
        for suite in &result.suites {
            html.push_str(&self.generate_suite_html(suite));
        }

        // Charts
        if self.config.include_charts {
            html.push_str(&self.generate_charts_html(result));
        }

        html.push_str("</body>\n</html>\n");
        html
    }

    fn generate_suite_html(&self, suite: &SuiteResult) -> String {
        let mut html = String::new();

        html.push_str("  <section class=\"suite\">\n");
        html.push_str(&format!("    <h2>{}</h2>\n", suite.name));
        html.push_str(&format!("    <p>Duration: {:.2?}</p>\n", suite.duration));

        html.push_str("    <table>\n");
        html.push_str("      <thead>\n");
        html.push_str("        <tr>\n");
        html.push_str("          <th>Benchmark</th>\n");
        html.push_str("          <th>Mean</th>\n");
        html.push_str("          <th>Median</th>\n");
        html.push_str("          <th>Std Dev</th>\n");
        html.push_str("          <th>P95</th>\n");
        html.push_str("          <th>P99</th>\n");
        html.push_str("          <th>Throughput</th>\n");
        html.push_str("        </tr>\n");
        html.push_str("      </thead>\n");
        html.push_str("      <tbody>\n");

        for result in &suite.results {
            html.push_str("        <tr>\n");
            html.push_str(&format!("          <td>{}</td>\n", result.name));
            html.push_str(&format!("          <td>{:.2?}</td>\n", result.mean()));
            html.push_str(&format!("          <td>{:.2?}</td>\n", result.median()));
            html.push_str(&format!("          <td>{:.2?}</td>\n", result.std_dev()));
            html.push_str(&format!("          <td>{:.2?}</td>\n", result.p95()));
            html.push_str(&format!("          <td>{:.2?}</td>\n", result.p99()));
            html.push_str(&format!(
                "          <td>{:.2}/s</td>\n",
                result.throughput()
            ));
            html.push_str("        </tr>\n");
        }

        html.push_str("      </tbody>\n");
        html.push_str("    </table>\n");
        html.push_str("  </section>\n");

        html
    }

    fn generate_charts_html(&self, result: &RunnerResult) -> String {
        let mut html = String::new();

        html.push_str("  <section class=\"charts\">\n");
        html.push_str("    <h2>Performance Charts</h2>\n");

        // Latency comparison chart
        html.push_str("    <div class=\"chart-container\">\n");
        html.push_str("      <canvas id=\"latencyChart\"></canvas>\n");
        html.push_str("    </div>\n");

        // Generate chart data
        let mut labels = Vec::new();
        let mut means = Vec::new();
        let mut p95s = Vec::new();
        let mut p99s = Vec::new();

        for suite in &result.suites {
            for bench in &suite.results {
                labels.push(bench.name.clone());
                means.push(bench.mean().as_micros() as f64);
                p95s.push(bench.p95().as_micros() as f64);
                p99s.push(bench.p99().as_micros() as f64);
            }
        }

        html.push_str("    <script>\n");
        html.push_str("      new Chart(document.getElementById('latencyChart'), {\n");
        html.push_str("        type: 'bar',\n");
        html.push_str("        data: {\n");
        html.push_str(&format!("          labels: {:?},\n", labels));
        html.push_str("          datasets: [{\n");
        html.push_str("            label: 'Mean (μs)',\n");
        html.push_str(&format!("            data: {:?},\n", means));
        html.push_str("            backgroundColor: 'rgba(54, 162, 235, 0.5)',\n");
        html.push_str("            borderColor: 'rgba(54, 162, 235, 1)',\n");
        html.push_str("            borderWidth: 1\n");
        html.push_str("          }, {\n");
        html.push_str("            label: 'P95 (μs)',\n");
        html.push_str(&format!("            data: {:?},\n", p95s));
        html.push_str("            backgroundColor: 'rgba(255, 206, 86, 0.5)',\n");
        html.push_str("            borderColor: 'rgba(255, 206, 86, 1)',\n");
        html.push_str("            borderWidth: 1\n");
        html.push_str("          }, {\n");
        html.push_str("            label: 'P99 (μs)',\n");
        html.push_str(&format!("            data: {:?},\n", p99s));
        html.push_str("            backgroundColor: 'rgba(255, 99, 132, 0.5)',\n");
        html.push_str("            borderColor: 'rgba(255, 99, 132, 1)',\n");
        html.push_str("            borderWidth: 1\n");
        html.push_str("          }]\n");
        html.push_str("        },\n");
        html.push_str("        options: {\n");
        html.push_str("          responsive: true,\n");
        html.push_str("          plugins: {\n");
        html.push_str("            title: {\n");
        html.push_str("              display: true,\n");
        html.push_str("              text: 'Latency Comparison'\n");
        html.push_str("            }\n");
        html.push_str("          },\n");
        html.push_str("          scales: {\n");
        html.push_str("            y: {\n");
        html.push_str("              beginAtZero: true,\n");
        html.push_str("              title: {\n");
        html.push_str("                display: true,\n");
        html.push_str("                text: 'Latency (μs)'\n");
        html.push_str("              }\n");
        html.push_str("            }\n");
        html.push_str("          }\n");
        html.push_str("        }\n");
        html.push_str("      });\n");
        html.push_str("    </script>\n");
        html.push_str("  </section>\n");

        html
    }

    /// Generate JSON report
    pub fn generate_json(&self, result: &RunnerResult) -> String {
        let data = serde_json::json!({
            "title": self.config.title,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "summary": {
                "total_benchmarks": result.total_benchmarks(),
                "total_suites": result.suites.len(),
                "duration_ms": result.duration.as_millis(),
            },
            "metadata": self.config.metadata,
            "suites": result.suites.iter().map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "duration_ms": s.duration.as_millis(),
                    "benchmarks": s.results.iter().map(|b| {
                        serde_json::json!({
                            "name": b.name,
                            "iterations": b.iterations,
                            "mean_ns": b.mean().as_nanos(),
                            "median_ns": b.median().as_nanos(),
                            "std_dev_ns": b.std_dev().as_nanos(),
                            "min_ns": b.min().as_nanos(),
                            "max_ns": b.max().as_nanos(),
                            "p50_ns": b.p50().as_nanos(),
                            "p95_ns": b.p95().as_nanos(),
                            "p99_ns": b.p99().as_nanos(),
                            "throughput": b.throughput(),
                        })
                    }).collect::<Vec<_>>(),
                })
            }).collect::<Vec<_>>(),
        });

        serde_json::to_string_pretty(&data).unwrap_or_default()
    }

    /// Generate CSV report
    pub fn generate_csv(&self, result: &RunnerResult) -> String {
        let mut csv = String::new();

        csv.push_str("suite,benchmark,iterations,mean_ns,median_ns,std_dev_ns,min_ns,max_ns,p50_ns,p95_ns,p99_ns,throughput\n");

        for suite in &result.suites {
            for bench in &suite.results {
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{:.4}\n",
                    suite.name,
                    bench.name,
                    bench.iterations,
                    bench.mean().as_nanos(),
                    bench.median().as_nanos(),
                    bench.std_dev().as_nanos(),
                    bench.min().as_nanos(),
                    bench.max().as_nanos(),
                    bench.p50().as_nanos(),
                    bench.p95().as_nanos(),
                    bench.p99().as_nanos(),
                    bench.throughput()
                ));
            }
        }

        csv
    }

    /// Generate markdown report
    pub fn generate_markdown(&self, result: &RunnerResult) -> String {
        let mut md = String::new();

        md.push_str(&format!("# {}\n\n", self.config.title));
        md.push_str(&format!(
            "_Generated: {}_\n\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Summary
        md.push_str("## Summary\n\n");
        md.push_str(&format!(
            "- **Total Benchmarks:** {}\n",
            result.total_benchmarks()
        ));
        md.push_str(&format!("- **Suites:** {}\n", result.suites.len()));
        md.push_str(&format!(
            "- **Total Duration:** {:.2?}\n\n",
            result.duration
        ));

        // Per-suite results
        for suite in &result.suites {
            md.push_str(&format!("## {}\n\n", suite.name));
            md.push_str(&format!("Duration: {:.2?}\n\n", suite.duration));

            md.push_str("| Benchmark | Mean | Median | P95 | P99 | Throughput |\n");
            md.push_str("|-----------|------|--------|-----|-----|------------|\n");

            for bench in &suite.results {
                md.push_str(&format!(
                    "| {} | {:.2?} | {:.2?} | {:.2?} | {:.2?} | {:.2}/s |\n",
                    bench.name,
                    bench.mean(),
                    bench.median(),
                    bench.p95(),
                    bench.p99(),
                    bench.throughput()
                ));
            }

            md.push('\n');
        }

        md
    }

    /// Save report to file
    pub fn save(&self, result: &RunnerResult, path: &Path) -> std::io::Result<()> {
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("html");

        let content = match extension {
            "html" => self.generate_html(result),
            "json" => self.generate_json(result),
            "csv" => self.generate_csv(result),
            "md" | "markdown" => self.generate_markdown(result),
            _ => self.generate_html(result),
        };

        fs::write(path, content)
    }
}

// ============ CSS Styles ============

const REPORT_CSS: &str = r#"
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        line-height: 1.6;
        color: #333;
        max-width: 1400px;
        margin: 0 auto;
        padding: 20px;
        background: #f5f7fa;
    }
    header {
        text-align: center;
        margin-bottom: 40px;
        padding: 30px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 12px;
        color: white;
    }
    header h1 { font-size: 2.5em; margin-bottom: 10px; }
    header .timestamp { opacity: 0.8; }
    section {
        background: white;
        border-radius: 12px;
        padding: 25px;
        margin-bottom: 25px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
    }
    h2 {
        color: #2d3748;
        margin-bottom: 20px;
        padding-bottom: 10px;
        border-bottom: 2px solid #e2e8f0;
    }
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px;
    }
    .stat {
        text-align: center;
        padding: 25px;
        background: #f7fafc;
        border-radius: 8px;
        border: 1px solid #e2e8f0;
    }
    .stat .value {
        display: block;
        font-size: 2em;
        font-weight: bold;
        color: #667eea;
    }
    .stat .label {
        display: block;
        color: #718096;
        margin-top: 5px;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 15px;
    }
    th, td {
        text-align: left;
        padding: 12px 15px;
        border-bottom: 1px solid #e2e8f0;
    }
    th {
        background: #f7fafc;
        font-weight: 600;
        color: #4a5568;
    }
    tr:hover td { background: #f7fafc; }
    .chart-container {
        margin: 30px 0;
        padding: 20px;
        background: #f7fafc;
        border-radius: 8px;
    }
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BenchmarkResult;
    use std::time::Duration;

    #[test]
    fn test_html_generation() {
        let suite = SuiteResult {
            name: "test_suite".to_string(),
            results: vec![BenchmarkResult::new(
                "bench1",
                vec![Duration::from_millis(10)],
            )],
            duration: Duration::from_secs(1),
        };

        let runner_result = RunnerResult {
            suites: vec![suite],
            duration: Duration::from_secs(1),
            config: crate::BenchmarkConfig::default(),
        };

        let config = ReportConfig::default();
        let generator = ReportGenerator::new(config);

        let html = generator.generate_html(&runner_result);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("test_suite"));
    }
}
