use aethelred_benchmarks::{BenchmarkConfig, BenchmarkRunner};

fn main() {
    let runner = BenchmarkRunner::new(BenchmarkConfig::default());
    let report = runner.run();
    println!("{}", report.format());
}
