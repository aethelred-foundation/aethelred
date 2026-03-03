//! Network Benchmarking Module
//!
//! Comprehensive network performance benchmarks for distributed AI/ML
//! including latency, throughput, connection pooling, and API performance.

use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::{BenchmarkResult, black_box};

// ============ Network Benchmark Config ============

/// Configuration for network benchmarks
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Target endpoints to test
    pub endpoints: Vec<String>,
    /// Payload sizes to test
    pub payload_sizes: Vec<usize>,
    /// Number of warmup requests
    pub warmup_requests: usize,
    /// Number of benchmark requests
    pub requests: usize,
    /// Concurrent connections to test
    pub concurrent_connections: Vec<usize>,
    /// Request timeout
    pub timeout: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            endpoints: vec!["http://localhost:8080".to_string()],
            payload_sizes: vec![1024, 10 * 1024, 100 * 1024, 1024 * 1024],
            warmup_requests: 10,
            requests: 100,
            concurrent_connections: vec![1, 10, 50, 100],
            timeout: Duration::from_secs(30),
        }
    }
}

// ============ Network Benchmark ============

/// Network benchmark runner
pub struct NetworkBenchmark {
    config: NetworkConfig,
}

impl NetworkBenchmark {
    pub fn new(config: NetworkConfig) -> Self {
        NetworkBenchmark { config }
    }

    /// Run all network benchmarks
    pub fn run_all(&self) -> NetworkResults {
        let mut results = NetworkResults {
            latency_results: Vec::new(),
            throughput_results: Vec::new(),
            concurrency_results: Vec::new(),
            connection_pool_results: Vec::new(),
        };

        // Latency benchmarks
        for &size in &self.config.payload_sizes {
            results.latency_results.push(self.benchmark_latency(size));
        }

        // Throughput benchmarks
        for &size in &self.config.payload_sizes {
            results.throughput_results.push(self.benchmark_throughput(size));
        }

        // Concurrency benchmarks
        for &concurrency in &self.config.concurrent_connections {
            results.concurrency_results.push(self.benchmark_concurrency(concurrency));
        }

        // Connection pool benchmark
        results.connection_pool_results = self.benchmark_connection_pool();

        results
    }

    /// Benchmark network latency
    pub fn benchmark_latency(&self, payload_size: usize) -> LatencyResult {
        let mut samples = Vec::with_capacity(self.config.requests);
        let mut ttfb_samples = Vec::with_capacity(self.config.requests);

        // Simulate network requests
        for _ in 0..self.config.requests {
            let (ttfb, total) = self.simulate_request(payload_size);
            ttfb_samples.push(ttfb);
            samples.push(total);
        }

        let benchmark = BenchmarkResult::new(
            format!("latency_{}b", payload_size),
            samples.clone(),
        );

        let ttfb_avg = Duration::from_nanos(
            (ttfb_samples.iter().map(|d| d.as_nanos()).sum::<u128>() / self.config.requests as u128) as u64
        );

        LatencyResult {
            payload_size,
            mean: benchmark.mean(),
            median: benchmark.median(),
            p50: benchmark.p50(),
            p95: benchmark.p95(),
            p99: benchmark.p99(),
            min: benchmark.min(),
            max: benchmark.max(),
            ttfb: ttfb_avg,
        }
    }

    /// Benchmark network throughput
    pub fn benchmark_throughput(&self, payload_size: usize) -> ThroughputResult {
        let duration = Duration::from_secs(5);
        let start = Instant::now();
        let mut total_bytes = 0usize;
        let mut request_count = 0usize;

        while start.elapsed() < duration {
            let _ = self.simulate_request(payload_size);
            total_bytes += payload_size;
            request_count += 1;
        }

        let elapsed = start.elapsed();
        let throughput_mbps = (total_bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;
        let requests_per_second = request_count as f64 / elapsed.as_secs_f64();

        ThroughputResult {
            payload_size,
            throughput_mbps,
            requests_per_second,
            total_bytes,
            duration: elapsed,
        }
    }

    /// Benchmark concurrent connections
    pub fn benchmark_concurrency(&self, num_connections: usize) -> ConcurrencyResult {
        use std::thread;
        use std::sync::mpsc;

        let payload_size = 10 * 1024; // 10 KB
        let requests_per_connection = self.config.requests / num_connections.max(1);

        let (tx, rx) = mpsc::channel();
        let start = Instant::now();

        // Spawn threads to simulate concurrent connections
        let mut handles = Vec::new();
        for _ in 0..num_connections {
            let tx = tx.clone();
            let requests = requests_per_connection;

            let handle = thread::spawn(move || {
                let mut latencies = Vec::new();

                for _ in 0..requests {
                    let req_start = Instant::now();
                    // Simulate request
                    let ops = payload_size / 10;
                    let _dummy: f32 = (0..ops).map(|i| (i as f32).sin()).sum();
                    latencies.push(req_start.elapsed());
                }

                tx.send(latencies).ok();
            });

            handles.push(handle);
        }

        drop(tx); // Close sender

        // Collect results
        let mut all_latencies = Vec::new();
        while let Ok(latencies) = rx.recv() {
            all_latencies.extend(latencies);
        }

        for handle in handles {
            handle.join().ok();
        }

        let total_duration = start.elapsed();
        let avg_latency = if !all_latencies.is_empty() {
            Duration::from_nanos(
                (all_latencies.iter().map(|d| d.as_nanos()).sum::<u128>() / all_latencies.len() as u128) as u64
            )
        } else {
            Duration::ZERO
        };

        let requests_per_second = all_latencies.len() as f64 / total_duration.as_secs_f64();

        ConcurrencyResult {
            num_connections,
            total_requests: all_latencies.len(),
            avg_latency,
            requests_per_second,
            duration: total_duration,
        }
    }

    /// Benchmark connection pooling
    pub fn benchmark_connection_pool(&self) -> Vec<ConnectionPoolResult> {
        let mut results = Vec::new();

        // Without pooling (new connection each time)
        let without_pool = self.benchmark_without_pool();

        // With pooling (simulated)
        let pool_sizes = vec![1, 5, 10, 25, 50];
        for pool_size in pool_sizes {
            let with_pool = self.benchmark_with_pool(pool_size);

            let speedup = without_pool.as_nanos() as f64 / with_pool.as_nanos() as f64;

            results.push(ConnectionPoolResult {
                pool_size,
                without_pool,
                with_pool,
                speedup,
            });
        }

        results
    }

    fn benchmark_without_pool(&self) -> Duration {
        let mut samples = Vec::with_capacity(self.config.requests);

        for _ in 0..self.config.requests {
            let start = Instant::now();
            // Simulate connection establishment (expensive)
            let _dummy: f32 = (0..1000).map(|i| (i as f32).sqrt()).sum();
            // Simulate request
            let _dummy2: f32 = (0..100).map(|i| (i as f32).sin()).sum();
            samples.push(start.elapsed());
        }

        Duration::from_nanos(
            (samples.iter().map(|d| d.as_nanos()).sum::<u128>() / samples.len() as u128) as u64
        )
    }

    fn benchmark_with_pool(&self, _pool_size: usize) -> Duration {
        let mut samples = Vec::with_capacity(self.config.requests);

        for _ in 0..self.config.requests {
            let start = Instant::now();
            // Skip connection establishment (reuse from pool)
            // Simulate request
            let _dummy: f32 = (0..100).map(|i| (i as f32).sin()).sum();
            samples.push(start.elapsed());
        }

        Duration::from_nanos(
            (samples.iter().map(|d| d.as_nanos()).sum::<u128>() / samples.len() as u128) as u64
        )
    }

    fn simulate_request(&self, payload_size: usize) -> (Duration, Duration) {
        let start = Instant::now();

        // Simulate time to first byte (connection + server processing)
        let ops = payload_size / 100;
        let _dummy: f32 = (0..ops.min(1000)).map(|i| (i as f32).sin()).sum();
        let ttfb = start.elapsed();

        // Simulate data transfer
        let _dummy2: f32 = (0..ops.min(1000)).map(|i| (i as f32).cos()).sum();
        let total = start.elapsed();

        (ttfb, total)
    }
}

// ============ Result Types ============

/// All network benchmark results
#[derive(Debug)]
pub struct NetworkResults {
    pub latency_results: Vec<LatencyResult>,
    pub throughput_results: Vec<ThroughputResult>,
    pub concurrency_results: Vec<ConcurrencyResult>,
    pub connection_pool_results: Vec<ConnectionPoolResult>,
}

impl NetworkResults {
    pub fn summary(&self) -> String {
        let mut s = String::new();
        s.push_str("Network Benchmark Results\n");
        s.push_str(&format!("{}\n\n", "=".repeat(50)));

        s.push_str("Latency by Payload Size:\n");
        for result in &self.latency_results {
            s.push_str(&format!(
                "  {:>8} bytes: mean={:>10.2?}, p95={:>10.2?}, p99={:>10.2?}\n",
                result.payload_size,
                result.mean,
                result.p95,
                result.p99
            ));
        }

        s.push_str("\nThroughput by Payload Size:\n");
        for result in &self.throughput_results {
            s.push_str(&format!(
                "  {:>8} bytes: {:.2} Mbps, {:.2} req/s\n",
                result.payload_size,
                result.throughput_mbps,
                result.requests_per_second
            ));
        }

        s.push_str("\nConcurrency Scaling:\n");
        for result in &self.concurrency_results {
            s.push_str(&format!(
                "  {:>3} connections: {:.2} req/s, avg latency={:.2?}\n",
                result.num_connections,
                result.requests_per_second,
                result.avg_latency
            ));
        }

        s.push_str("\nConnection Pool Performance:\n");
        for result in &self.connection_pool_results {
            s.push_str(&format!(
                "  pool_size={:>2}: {:.2}x speedup\n",
                result.pool_size,
                result.speedup
            ));
        }

        s
    }
}

#[derive(Debug, Clone)]
pub struct LatencyResult {
    pub payload_size: usize,
    pub mean: Duration,
    pub median: Duration,
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub min: Duration,
    pub max: Duration,
    pub ttfb: Duration,
}

#[derive(Debug, Clone)]
pub struct ThroughputResult {
    pub payload_size: usize,
    pub throughput_mbps: f64,
    pub requests_per_second: f64,
    pub total_bytes: usize,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
pub struct ConcurrencyResult {
    pub num_connections: usize,
    pub total_requests: usize,
    pub avg_latency: Duration,
    pub requests_per_second: f64,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
pub struct ConnectionPoolResult {
    pub pool_size: usize,
    pub without_pool: Duration,
    pub with_pool: Duration,
    pub speedup: f64,
}

// ============ API Benchmark ============

/// Benchmark API endpoints
pub struct ApiBenchmark {
    config: NetworkConfig,
    endpoints: HashMap<String, ApiEndpoint>,
}

#[derive(Debug, Clone)]
pub struct ApiEndpoint {
    pub name: String,
    pub method: String,
    pub path: String,
    pub payload: Option<Vec<u8>>,
}

impl ApiBenchmark {
    pub fn new(config: NetworkConfig) -> Self {
        ApiBenchmark {
            config,
            endpoints: HashMap::new(),
        }
    }

    pub fn add_endpoint(&mut self, endpoint: ApiEndpoint) -> &mut Self {
        self.endpoints.insert(endpoint.name.clone(), endpoint);
        self
    }

    /// Benchmark a specific endpoint
    pub fn benchmark_endpoint(&self, name: &str) -> Option<ApiResult> {
        let endpoint = self.endpoints.get(name)?;

        let mut samples = Vec::with_capacity(self.config.requests);
        let mut error_count = 0;

        for _ in 0..self.config.requests {
            let start = Instant::now();
            let success = self.simulate_api_call(endpoint);
            let duration = start.elapsed();

            if success {
                samples.push(duration);
            } else {
                error_count += 1;
            }
        }

        if samples.is_empty() {
            return None;
        }

        let benchmark = BenchmarkResult::new(&endpoint.name, samples.clone());
        let success_rate = (self.config.requests - error_count) as f64 / self.config.requests as f64 * 100.0;

        Some(ApiResult {
            endpoint_name: endpoint.name.clone(),
            mean: benchmark.mean(),
            median: benchmark.median(),
            p95: benchmark.p95(),
            p99: benchmark.p99(),
            success_rate,
            error_count,
            requests: self.config.requests,
        })
    }

    /// Benchmark all endpoints
    pub fn benchmark_all(&self) -> Vec<ApiResult> {
        self.endpoints.keys()
            .filter_map(|name| self.benchmark_endpoint(name))
            .collect()
    }

    fn simulate_api_call(&self, endpoint: &ApiEndpoint) -> bool {
        // Simulate API call with some processing
        let ops = endpoint.payload.as_ref().map(|p| p.len()).unwrap_or(100);
        let _dummy: f32 = (0..ops.min(1000)).map(|i| (i as f32).sin()).sum();

        // Simulate 99% success rate
        rand::random::<f64>() > 0.01
    }
}

#[derive(Debug, Clone)]
pub struct ApiResult {
    pub endpoint_name: String,
    pub mean: Duration,
    pub median: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub success_rate: f64,
    pub error_count: usize,
    pub requests: usize,
}

// ============ gRPC Benchmark ============

/// Benchmark gRPC performance
pub struct GrpcBenchmark {
    config: NetworkConfig,
}

impl GrpcBenchmark {
    pub fn new(config: NetworkConfig) -> Self {
        GrpcBenchmark { config }
    }

    /// Benchmark unary RPC
    pub fn benchmark_unary(&self, payload_size: usize) -> BenchmarkResult {
        let mut samples = Vec::with_capacity(self.config.requests);

        for _ in 0..self.config.requests {
            let start = Instant::now();
            self.simulate_unary(payload_size);
            samples.push(start.elapsed());
        }

        BenchmarkResult::new(format!("grpc_unary_{}b", payload_size), samples)
    }

    /// Benchmark streaming RPC
    pub fn benchmark_streaming(&self, num_messages: usize, message_size: usize) -> StreamingResult {
        let start = Instant::now();
        let mut message_times = Vec::with_capacity(num_messages);

        for _ in 0..num_messages {
            let msg_start = Instant::now();
            self.simulate_stream_message(message_size);
            message_times.push(msg_start.elapsed());
        }

        let total_duration = start.elapsed();
        let avg_message_time = Duration::from_nanos(
            (message_times.iter().map(|d| d.as_nanos()).sum::<u128>() / num_messages as u128) as u64
        );

        StreamingResult {
            num_messages,
            message_size,
            total_duration,
            avg_message_time,
            messages_per_second: num_messages as f64 / total_duration.as_secs_f64(),
        }
    }

    fn simulate_unary(&self, payload_size: usize) {
        let ops = payload_size / 10;
        let _dummy: f32 = (0..ops.min(1000)).map(|i| (i as f32).sin()).sum();
    }

    fn simulate_stream_message(&self, message_size: usize) {
        let ops = message_size / 100;
        let _dummy: f32 = (0..ops.min(100)).map(|i| (i as f32).cos()).sum();
    }
}

#[derive(Debug, Clone)]
pub struct StreamingResult {
    pub num_messages: usize,
    pub message_size: usize,
    pub total_duration: Duration,
    pub avg_message_time: Duration,
    pub messages_per_second: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_benchmark() {
        let config = NetworkConfig {
            payload_sizes: vec![1024],
            requests: 10,
            warmup_requests: 2,
            concurrent_connections: vec![1, 2],
            ..Default::default()
        };

        let bench = NetworkBenchmark::new(config);
        let results = bench.run_all();

        assert!(!results.latency_results.is_empty());
    }

    #[test]
    fn test_concurrency_benchmark() {
        let config = NetworkConfig {
            requests: 20,
            ..Default::default()
        };

        let bench = NetworkBenchmark::new(config);
        let result = bench.benchmark_concurrency(2);

        assert!(result.requests_per_second > 0.0);
    }

    #[test]
    fn test_grpc_benchmark() {
        let config = NetworkConfig {
            requests: 10,
            ..Default::default()
        };

        let bench = GrpcBenchmark::new(config);
        let result = bench.benchmark_unary(1024);

        assert_eq!(result.iterations, 10);
    }
}
