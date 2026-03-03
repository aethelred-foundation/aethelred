//! Aethelred SDK Coverage Analysis
//!
//! Code coverage tracking and reporting for AI/ML SDK testing.
//! Provides line, branch, and function coverage analysis.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

// ============ Coverage Data ============

/// Coverage data for a single file
#[derive(Debug, Clone)]
pub struct FileCoverage {
    pub path: PathBuf,
    pub lines: HashMap<usize, LineCoverage>,
    pub functions: HashMap<String, FunctionCoverage>,
    pub branches: Vec<BranchCoverage>,
}

impl FileCoverage {
    pub fn new(path: PathBuf) -> Self {
        FileCoverage {
            path,
            lines: HashMap::new(),
            functions: HashMap::new(),
            branches: Vec::new(),
        }
    }

    /// Get line coverage percentage
    pub fn line_coverage(&self) -> f64 {
        if self.lines.is_empty() {
            return 100.0;
        }
        let covered = self.lines.values().filter(|l| l.hit_count > 0).count();
        covered as f64 / self.lines.len() as f64 * 100.0
    }

    /// Get function coverage percentage
    pub fn function_coverage(&self) -> f64 {
        if self.functions.is_empty() {
            return 100.0;
        }
        let covered = self.functions.values().filter(|f| f.hit_count > 0).count();
        covered as f64 / self.functions.len() as f64 * 100.0
    }

    /// Get branch coverage percentage
    pub fn branch_coverage(&self) -> f64 {
        if self.branches.is_empty() {
            return 100.0;
        }
        let covered = self.branches.iter().filter(|b| b.taken).count();
        covered as f64 / self.branches.len() as f64 * 100.0
    }

    /// Mark a line as covered
    pub fn cover_line(&mut self, line: usize) {
        self.lines
            .entry(line)
            .or_insert(LineCoverage { hit_count: 0 })
            .hit_count += 1;
    }

    /// Mark a function as covered
    pub fn cover_function(&mut self, name: &str) {
        self.functions
            .entry(name.to_string())
            .or_insert(FunctionCoverage {
                name: name.to_string(),
                start_line: 0,
                end_line: 0,
                hit_count: 0,
            })
            .hit_count += 1;
    }

    /// Add a branch point
    pub fn add_branch(&mut self, line: usize, condition: &str, taken: bool) {
        self.branches.push(BranchCoverage {
            line,
            condition: condition.to_string(),
            taken,
        });
    }
}

/// Coverage data for a single line
#[derive(Debug, Clone)]
pub struct LineCoverage {
    pub hit_count: usize,
}

/// Coverage data for a function
#[derive(Debug, Clone)]
pub struct FunctionCoverage {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub hit_count: usize,
}

/// Coverage data for a branch
#[derive(Debug, Clone)]
pub struct BranchCoverage {
    pub line: usize,
    pub condition: String,
    pub taken: bool,
}

// ============ Coverage Collector ============

/// Collects coverage data during test execution
pub struct CoverageCollector {
    data: Arc<RwLock<CoverageData>>,
    enabled: bool,
}

#[derive(Debug, Default)]
struct CoverageData {
    files: HashMap<PathBuf, FileCoverage>,
    excluded_paths: HashSet<PathBuf>,
}

impl CoverageCollector {
    pub fn new() -> Self {
        CoverageCollector {
            data: Arc::new(RwLock::new(CoverageData::default())),
            enabled: true,
        }
    }

    pub fn disabled() -> Self {
        CoverageCollector {
            data: Arc::new(RwLock::new(CoverageData::default())),
            enabled: false,
        }
    }

    /// Add a path to exclude from coverage
    pub fn exclude(&self, path: impl AsRef<Path>) {
        if let Ok(mut data) = self.data.write() {
            data.excluded_paths.insert(path.as_ref().to_path_buf());
        }
    }

    /// Record a line hit
    pub fn record_line(&self, file: impl AsRef<Path>, line: usize) {
        if !self.enabled {
            return;
        }

        if let Ok(mut data) = self.data.write() {
            let path = file.as_ref().to_path_buf();
            if data.excluded_paths.contains(&path) {
                return;
            }

            data.files
                .entry(path.clone())
                .or_insert_with(|| FileCoverage::new(path))
                .cover_line(line);
        }
    }

    /// Record a function hit
    pub fn record_function(&self, file: impl AsRef<Path>, function: &str) {
        if !self.enabled {
            return;
        }

        if let Ok(mut data) = self.data.write() {
            let path = file.as_ref().to_path_buf();
            if data.excluded_paths.contains(&path) {
                return;
            }

            data.files
                .entry(path.clone())
                .or_insert_with(|| FileCoverage::new(path))
                .cover_function(function);
        }
    }

    /// Record a branch
    pub fn record_branch(&self, file: impl AsRef<Path>, line: usize, condition: &str, taken: bool) {
        if !self.enabled {
            return;
        }

        if let Ok(mut data) = self.data.write() {
            let path = file.as_ref().to_path_buf();
            if data.excluded_paths.contains(&path) {
                return;
            }

            data.files
                .entry(path.clone())
                .or_insert_with(|| FileCoverage::new(path))
                .add_branch(line, condition, taken);
        }
    }

    /// Get coverage report
    pub fn report(&self) -> CoverageReport {
        let data = self.data.read().unwrap();

        let files: Vec<FileCoverage> = data.files.values().cloned().collect();

        let total_lines: usize = files.iter().map(|f| f.lines.len()).sum();
        let covered_lines: usize = files.iter()
            .flat_map(|f| f.lines.values())
            .filter(|l| l.hit_count > 0)
            .count();

        let total_functions: usize = files.iter().map(|f| f.functions.len()).sum();
        let covered_functions: usize = files.iter()
            .flat_map(|f| f.functions.values())
            .filter(|f| f.hit_count > 0)
            .count();

        let total_branches: usize = files.iter().map(|f| f.branches.len()).sum();
        let covered_branches: usize = files.iter()
            .flat_map(|f| f.branches.iter())
            .filter(|b| b.taken)
            .count();

        CoverageReport {
            files,
            summary: CoverageSummary {
                total_lines,
                covered_lines,
                line_coverage: if total_lines > 0 {
                    covered_lines as f64 / total_lines as f64 * 100.0
                } else {
                    100.0
                },
                total_functions,
                covered_functions,
                function_coverage: if total_functions > 0 {
                    covered_functions as f64 / total_functions as f64 * 100.0
                } else {
                    100.0
                },
                total_branches,
                covered_branches,
                branch_coverage: if total_branches > 0 {
                    covered_branches as f64 / total_branches as f64 * 100.0
                } else {
                    100.0
                },
            },
        }
    }

    /// Reset coverage data
    pub fn reset(&self) {
        if let Ok(mut data) = self.data.write() {
            data.files.clear();
        }
    }
}

impl Default for CoverageCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for CoverageCollector {
    fn clone(&self) -> Self {
        CoverageCollector {
            data: Arc::clone(&self.data),
            enabled: self.enabled,
        }
    }
}

// ============ Coverage Report ============

/// Coverage report
#[derive(Debug, Clone)]
pub struct CoverageReport {
    pub files: Vec<FileCoverage>,
    pub summary: CoverageSummary,
}

/// Summary of coverage data
#[derive(Debug, Clone)]
pub struct CoverageSummary {
    pub total_lines: usize,
    pub covered_lines: usize,
    pub line_coverage: f64,
    pub total_functions: usize,
    pub covered_functions: usize,
    pub function_coverage: f64,
    pub total_branches: usize,
    pub covered_branches: usize,
    pub branch_coverage: f64,
}

impl CoverageReport {
    /// Check if coverage meets threshold
    pub fn meets_threshold(&self, line_threshold: f64, function_threshold: f64, branch_threshold: f64) -> bool {
        self.summary.line_coverage >= line_threshold
            && self.summary.function_coverage >= function_threshold
            && self.summary.branch_coverage >= branch_threshold
    }

    /// Get files below threshold
    pub fn files_below_threshold(&self, threshold: f64) -> Vec<&FileCoverage> {
        self.files.iter()
            .filter(|f| f.line_coverage() < threshold)
            .collect()
    }

    /// Get uncovered lines for a file
    pub fn uncovered_lines(&self, file: &Path) -> Vec<usize> {
        self.files.iter()
            .find(|f| f.path == file)
            .map(|f| {
                f.lines.iter()
                    .filter(|(_, l)| l.hit_count == 0)
                    .map(|(line, _)| *line)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Generate text report
    pub fn to_text(&self) -> String {
        let mut output = String::new();

        output.push_str("Coverage Report\n");
        output.push_str("===============\n\n");

        output.push_str(&format!(
            "Line Coverage:     {:.1}% ({}/{})\n",
            self.summary.line_coverage,
            self.summary.covered_lines,
            self.summary.total_lines
        ));
        output.push_str(&format!(
            "Function Coverage: {:.1}% ({}/{})\n",
            self.summary.function_coverage,
            self.summary.covered_functions,
            self.summary.total_functions
        ));
        output.push_str(&format!(
            "Branch Coverage:   {:.1}% ({}/{})\n",
            self.summary.branch_coverage,
            self.summary.covered_branches,
            self.summary.total_branches
        ));

        output.push_str("\nPer-File Coverage:\n");
        output.push_str("-----------------\n");

        for file in &self.files {
            output.push_str(&format!(
                "{}: {:.1}% lines, {:.1}% functions, {:.1}% branches\n",
                file.path.display(),
                file.line_coverage(),
                file.function_coverage(),
                file.branch_coverage()
            ));
        }

        output
    }

    /// Generate LCOV format report
    pub fn to_lcov(&self) -> String {
        let mut output = String::new();

        for file in &self.files {
            output.push_str(&format!("SF:{}\n", file.path.display()));

            // Functions
            for (name, func) in &file.functions {
                output.push_str(&format!("FN:{},{}\n", func.start_line, name));
            }
            for (name, func) in &file.functions {
                output.push_str(&format!("FNDA:{},{}\n", func.hit_count, name));
            }
            output.push_str(&format!(
                "FNF:{}\n",
                file.functions.len()
            ));
            output.push_str(&format!(
                "FNH:{}\n",
                file.functions.values().filter(|f| f.hit_count > 0).count()
            ));

            // Branches
            for (i, branch) in file.branches.iter().enumerate() {
                output.push_str(&format!(
                    "BRDA:{},0,{},{}\n",
                    branch.line,
                    i,
                    if branch.taken { 1 } else { 0 }
                ));
            }
            output.push_str(&format!("BRF:{}\n", file.branches.len()));
            output.push_str(&format!(
                "BRH:{}\n",
                file.branches.iter().filter(|b| b.taken).count()
            ));

            // Lines
            let mut sorted_lines: Vec<_> = file.lines.iter().collect();
            sorted_lines.sort_by_key(|(line, _)| *line);
            for (line, coverage) in sorted_lines {
                output.push_str(&format!("DA:{},{}\n", line, coverage.hit_count));
            }
            output.push_str(&format!("LF:{}\n", file.lines.len()));
            output.push_str(&format!(
                "LH:{}\n",
                file.lines.values().filter(|l| l.hit_count > 0).count()
            ));

            output.push_str("end_of_record\n");
        }

        output
    }

    /// Generate Cobertura XML format
    pub fn to_cobertura(&self) -> String {
        let mut xml = String::new();

        xml.push_str("<?xml version=\"1.0\"?>\n");
        xml.push_str("<!DOCTYPE coverage SYSTEM \"http://cobertura.sourceforge.net/xml/coverage-04.dtd\">\n");
        xml.push_str(&format!(
            "<coverage line-rate=\"{:.4}\" branch-rate=\"{:.4}\" version=\"1.0\">\n",
            self.summary.line_coverage / 100.0,
            self.summary.branch_coverage / 100.0
        ));

        xml.push_str("  <packages>\n");
        xml.push_str("    <package name=\".\" line-rate=\"1.0\" branch-rate=\"1.0\">\n");
        xml.push_str("      <classes>\n");

        for file in &self.files {
            let filename = file.path.file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default();

            xml.push_str(&format!(
                "        <class name=\"{}\" filename=\"{}\" line-rate=\"{:.4}\">\n",
                filename,
                file.path.display(),
                file.line_coverage() / 100.0
            ));

            xml.push_str("          <lines>\n");
            let mut sorted_lines: Vec<_> = file.lines.iter().collect();
            sorted_lines.sort_by_key(|(line, _)| *line);
            for (line, coverage) in sorted_lines {
                xml.push_str(&format!(
                    "            <line number=\"{}\" hits=\"{}\"/>\n",
                    line, coverage.hit_count
                ));
            }
            xml.push_str("          </lines>\n");
            xml.push_str("        </class>\n");
        }

        xml.push_str("      </classes>\n");
        xml.push_str("    </package>\n");
        xml.push_str("  </packages>\n");
        xml.push_str("</coverage>\n");

        xml
    }

    /// Generate HTML report
    pub fn to_html(&self) -> String {
        let mut html = String::new();

        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("  <title>Coverage Report</title>\n");
        html.push_str("  <style>\n");
        html.push_str(COVERAGE_CSS);
        html.push_str("  </style>\n");
        html.push_str("</head>\n<body>\n");

        html.push_str("  <h1>Coverage Report</h1>\n");

        // Summary
        html.push_str("  <div class=\"summary\">\n");
        html.push_str(&format!(
            "    <div class=\"metric\">\n      <span class=\"label\">Line Coverage</span>\n      <span class=\"value\">{:.1}%</span>\n    </div>\n",
            self.summary.line_coverage
        ));
        html.push_str(&format!(
            "    <div class=\"metric\">\n      <span class=\"label\">Function Coverage</span>\n      <span class=\"value\">{:.1}%</span>\n    </div>\n",
            self.summary.function_coverage
        ));
        html.push_str(&format!(
            "    <div class=\"metric\">\n      <span class=\"label\">Branch Coverage</span>\n      <span class=\"value\">{:.1}%</span>\n    </div>\n",
            self.summary.branch_coverage
        ));
        html.push_str("  </div>\n");

        // File list
        html.push_str("  <h2>Files</h2>\n");
        html.push_str("  <table>\n");
        html.push_str("    <tr><th>File</th><th>Lines</th><th>Functions</th><th>Branches</th></tr>\n");

        for file in &self.files {
            let line_class = coverage_class(file.line_coverage());
            html.push_str(&format!(
                "    <tr><td>{}</td><td class=\"{}\">{:.1}%</td><td class=\"{}\">{:.1}%</td><td class=\"{}\">{:.1}%</td></tr>\n",
                file.path.display(),
                line_class,
                file.line_coverage(),
                coverage_class(file.function_coverage()),
                file.function_coverage(),
                coverage_class(file.branch_coverage()),
                file.branch_coverage()
            ));
        }

        html.push_str("  </table>\n");
        html.push_str("</body>\n</html>\n");

        html
    }
}

fn coverage_class(coverage: f64) -> &'static str {
    if coverage >= 80.0 {
        "high"
    } else if coverage >= 50.0 {
        "medium"
    } else {
        "low"
    }
}

const COVERAGE_CSS: &str = r#"
    body { font-family: sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
    h1 { color: #333; }
    .summary { display: flex; gap: 20px; margin: 20px 0; }
    .metric {
      background: #f5f5f5;
      padding: 15px 25px;
      border-radius: 8px;
      text-align: center;
    }
    .metric .label { display: block; color: #666; margin-bottom: 5px; }
    .metric .value { font-size: 24px; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background: #f5f5f5; }
    .high { color: #4caf50; }
    .medium { color: #ff9800; }
    .low { color: #f44336; }
"#;

// ============ Coverage Thresholds ============

/// Coverage threshold configuration
#[derive(Debug, Clone)]
pub struct CoverageThresholds {
    pub line: f64,
    pub function: f64,
    pub branch: f64,
}

impl Default for CoverageThresholds {
    fn default() -> Self {
        CoverageThresholds {
            line: 80.0,
            function: 80.0,
            branch: 70.0,
        }
    }
}

impl CoverageThresholds {
    pub fn strict() -> Self {
        CoverageThresholds {
            line: 90.0,
            function: 90.0,
            branch: 80.0,
        }
    }

    pub fn relaxed() -> Self {
        CoverageThresholds {
            line: 60.0,
            function: 60.0,
            branch: 50.0,
        }
    }

    pub fn check(&self, report: &CoverageReport) -> ThresholdResult {
        let mut failures = Vec::new();

        if report.summary.line_coverage < self.line {
            failures.push(format!(
                "Line coverage {:.1}% is below threshold {:.1}%",
                report.summary.line_coverage, self.line
            ));
        }

        if report.summary.function_coverage < self.function {
            failures.push(format!(
                "Function coverage {:.1}% is below threshold {:.1}%",
                report.summary.function_coverage, self.function
            ));
        }

        if report.summary.branch_coverage < self.branch {
            failures.push(format!(
                "Branch coverage {:.1}% is below threshold {:.1}%",
                report.summary.branch_coverage, self.branch
            ));
        }

        if failures.is_empty() {
            ThresholdResult::Pass
        } else {
            ThresholdResult::Fail(failures)
        }
    }
}

/// Result of threshold check
#[derive(Debug)]
pub enum ThresholdResult {
    Pass,
    Fail(Vec<String>),
}

impl ThresholdResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, ThresholdResult::Pass)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coverage_collector() {
        let collector = CoverageCollector::new();

        collector.record_line("test.rs", 1);
        collector.record_line("test.rs", 2);
        collector.record_line("test.rs", 1);
        collector.record_function("test.rs", "test_fn");

        let report = collector.report();
        assert_eq!(report.summary.covered_lines, 2);
    }

    #[test]
    fn test_file_coverage() {
        let mut file = FileCoverage::new(PathBuf::from("test.rs"));
        file.cover_line(1);
        file.cover_line(2);
        file.lines.insert(3, LineCoverage { hit_count: 0 });

        // 2 covered out of 3
        assert!((file.line_coverage() - 66.66).abs() < 1.0);
    }

    #[test]
    fn test_thresholds() {
        let report = CoverageReport {
            files: vec![],
            summary: CoverageSummary {
                total_lines: 100,
                covered_lines: 75,
                line_coverage: 75.0,
                total_functions: 10,
                covered_functions: 8,
                function_coverage: 80.0,
                total_branches: 20,
                covered_branches: 15,
                branch_coverage: 75.0,
            },
        };

        let thresholds = CoverageThresholds::default();
        let result = thresholds.check(&report);

        assert!(!result.is_pass()); // Line coverage below 80%
    }
}
