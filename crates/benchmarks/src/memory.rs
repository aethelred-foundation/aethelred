//! Memory Benchmarking Module
//!
//! Comprehensive memory profiling for AI/ML applications including
//! allocation tracking, peak memory usage, memory bandwidth,
//! and fragmentation analysis.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::collections::HashMap;

use crate::BenchmarkResult;

// ============ Memory Tracker ============

/// Global memory allocator wrapper for tracking
pub struct TrackingAllocator {
    inner: System,
    current: AtomicUsize,
    peak: AtomicUsize,
    total_allocated: AtomicUsize,
    total_freed: AtomicUsize,
    allocation_count: AtomicUsize,
}

impl TrackingAllocator {
    pub const fn new() -> Self {
        TrackingAllocator {
            inner: System,
            current: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            total_allocated: AtomicUsize::new(0),
            total_freed: AtomicUsize::new(0),
            allocation_count: AtomicUsize::new(0),
        }
    }

    pub fn current_usage(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }

    pub fn peak_usage(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    pub fn total_allocated(&self) -> usize {
        self.total_allocated.load(Ordering::Relaxed)
    }

    pub fn total_freed(&self) -> usize {
        self.total_freed.load(Ordering::Relaxed)
    }

    pub fn allocation_count(&self) -> usize {
        self.allocation_count.load(Ordering::Relaxed)
    }

    pub fn reset(&self) {
        self.current.store(0, Ordering::Relaxed);
        self.peak.store(0, Ordering::Relaxed);
        self.total_allocated.store(0, Ordering::Relaxed);
        self.total_freed.store(0, Ordering::Relaxed);
        self.allocation_count.store(0, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = self.inner.alloc(layout);
        if !ptr.is_null() {
            let size = layout.size();
            self.current.fetch_add(size, Ordering::Relaxed);
            self.total_allocated.fetch_add(size, Ordering::Relaxed);
            self.allocation_count.fetch_add(1, Ordering::Relaxed);

            // Update peak
            let current = self.current.load(Ordering::Relaxed);
            let mut peak = self.peak.load(Ordering::Relaxed);
            while current > peak {
                match self.peak.compare_exchange_weak(
                    peak,
                    current,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(p) => peak = p,
                }
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.inner.dealloc(ptr, layout);
        let size = layout.size();
        self.current.fetch_sub(size, Ordering::Relaxed);
        self.total_freed.fetch_add(size, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let old_size = layout.size();
        let new_ptr = self.inner.realloc(ptr, layout, new_size);

        if !new_ptr.is_null() {
            if new_size > old_size {
                let diff = new_size - old_size;
                self.current.fetch_add(diff, Ordering::Relaxed);
                self.total_allocated.fetch_add(diff, Ordering::Relaxed);
            } else {
                let diff = old_size - new_size;
                self.current.fetch_sub(diff, Ordering::Relaxed);
                self.total_freed.fetch_add(diff, Ordering::Relaxed);
            }

            // Update peak
            let current = self.current.load(Ordering::Relaxed);
            let mut peak = self.peak.load(Ordering::Relaxed);
            while current > peak {
                match self.peak.compare_exchange_weak(
                    peak,
                    current,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(p) => peak = p,
                }
            }
        }

        new_ptr
    }
}

// ============ Memory Benchmark ============

/// Configuration for memory benchmarks
#[derive(Debug, Clone)]
pub struct MemoryBenchmarkConfig {
    /// Allocation sizes to test
    pub allocation_sizes: Vec<usize>,
    /// Number of iterations
    pub iterations: usize,
    /// Test fragmentation
    pub test_fragmentation: bool,
    /// Test bandwidth
    pub test_bandwidth: bool,
}

impl Default for MemoryBenchmarkConfig {
    fn default() -> Self {
        MemoryBenchmarkConfig {
            allocation_sizes: vec![
                1024,           // 1 KB
                1024 * 1024,    // 1 MB
                10 * 1024 * 1024,   // 10 MB
                100 * 1024 * 1024,  // 100 MB
            ],
            iterations: 100,
            test_fragmentation: true,
            test_bandwidth: true,
        }
    }
}

/// Memory benchmark runner
pub struct MemoryBenchmark {
    config: MemoryBenchmarkConfig,
}

impl MemoryBenchmark {
    pub fn new(config: MemoryBenchmarkConfig) -> Self {
        MemoryBenchmark { config }
    }

    /// Run all memory benchmarks
    pub fn run_all(&self) -> MemoryResults {
        let mut results = MemoryResults {
            allocation_results: Vec::new(),
            bandwidth_results: Vec::new(),
            fragmentation_result: None,
            pool_results: Vec::new(),
        };

        // Allocation benchmarks
        for &size in &self.config.allocation_sizes {
            results.allocation_results.push(self.benchmark_allocation(size));
        }

        // Bandwidth benchmarks
        if self.config.test_bandwidth {
            for &size in &self.config.allocation_sizes {
                results.bandwidth_results.push(self.benchmark_bandwidth(size));
            }
        }

        // Fragmentation benchmark
        if self.config.test_fragmentation {
            results.fragmentation_result = Some(self.benchmark_fragmentation());
        }

        // Memory pool benchmarks
        results.pool_results.push(self.benchmark_memory_pool(1024));
        results.pool_results.push(self.benchmark_memory_pool(1024 * 1024));

        results
    }

    /// Benchmark allocation/deallocation speed
    pub fn benchmark_allocation(&self, size: usize) -> AllocationResult {
        let mut alloc_times = Vec::with_capacity(self.config.iterations);
        let mut dealloc_times = Vec::with_capacity(self.config.iterations);

        for _ in 0..self.config.iterations {
            // Allocation
            let alloc_start = Instant::now();
            let data: Vec<u8> = vec![0u8; size];
            alloc_times.push(alloc_start.elapsed());

            // Touch memory to ensure it's actually allocated
            std::hint::black_box(&data);

            // Deallocation
            let dealloc_start = Instant::now();
            drop(data);
            dealloc_times.push(dealloc_start.elapsed());
        }

        let alloc_avg = Duration::from_nanos(
            (alloc_times.iter().map(|d| d.as_nanos()).sum::<u128>() / self.config.iterations as u128) as u64
        );
        let dealloc_avg = Duration::from_nanos(
            (dealloc_times.iter().map(|d| d.as_nanos()).sum::<u128>() / self.config.iterations as u128) as u64
        );

        AllocationResult {
            size,
            alloc_mean: alloc_avg,
            dealloc_mean: dealloc_avg,
            alloc_throughput: size as f64 / alloc_avg.as_secs_f64() / 1024.0 / 1024.0, // MB/s
        }
    }

    /// Benchmark memory bandwidth
    pub fn benchmark_bandwidth(&self, size: usize) -> BandwidthResult {
        let mut read_times = Vec::with_capacity(self.config.iterations);
        let mut write_times = Vec::with_capacity(self.config.iterations);
        let mut copy_times = Vec::with_capacity(self.config.iterations);

        // Allocate source and destination
        let src: Vec<u8> = vec![1u8; size];
        let mut dst: Vec<u8> = vec![0u8; size];

        for _ in 0..self.config.iterations {
            // Read bandwidth
            let read_start = Instant::now();
            let _sum: u64 = src.iter().map(|&x| x as u64).sum();
            read_times.push(read_start.elapsed());

            // Write bandwidth
            let write_start = Instant::now();
            for byte in dst.iter_mut() {
                *byte = 1;
            }
            write_times.push(write_start.elapsed());

            // Copy bandwidth
            let copy_start = Instant::now();
            dst.copy_from_slice(&src);
            copy_times.push(copy_start.elapsed());
        }

        let read_avg = Duration::from_nanos(
            (read_times.iter().map(|d| d.as_nanos()).sum::<u128>() / self.config.iterations as u128) as u64
        );
        let write_avg = Duration::from_nanos(
            (write_times.iter().map(|d| d.as_nanos()).sum::<u128>() / self.config.iterations as u128) as u64
        );
        let copy_avg = Duration::from_nanos(
            (copy_times.iter().map(|d| d.as_nanos()).sum::<u128>() / self.config.iterations as u128) as u64
        );

        let bytes_to_gbps = |bytes: usize, duration: Duration| -> f64 {
            bytes as f64 / duration.as_secs_f64() / 1024.0 / 1024.0 / 1024.0
        };

        BandwidthResult {
            size,
            read_bandwidth_gbps: bytes_to_gbps(size, read_avg),
            write_bandwidth_gbps: bytes_to_gbps(size, write_avg),
            copy_bandwidth_gbps: bytes_to_gbps(size * 2, copy_avg), // Read + Write
        }
    }

    /// Benchmark memory fragmentation
    pub fn benchmark_fragmentation(&self) -> FragmentationResult {
        let allocation_size = 1024 * 1024; // 1 MB
        let num_allocations = 100;

        // Phase 1: Allocate many blocks
        let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(num_allocations);
        let alloc_start = Instant::now();
        for _ in 0..num_allocations {
            blocks.push(vec![0u8; allocation_size]);
        }
        let initial_alloc_time = alloc_start.elapsed();

        // Phase 2: Free every other block (creates fragmentation)
        let indices_to_free: Vec<usize> = (0..num_allocations).step_by(2).collect();
        for &i in indices_to_free.iter().rev() {
            let _ = blocks.swap_remove(i);
        }

        // Phase 3: Allocate new blocks (into fragmented heap)
        let fragmented_start = Instant::now();
        for _ in 0..indices_to_free.len() {
            blocks.push(vec![0u8; allocation_size]);
        }
        let fragmented_alloc_time = fragmented_start.elapsed();

        // Calculate fragmentation impact
        let avg_initial = initial_alloc_time / num_allocations as u32;
        let avg_fragmented = fragmented_alloc_time / indices_to_free.len() as u32;
        let fragmentation_overhead = avg_fragmented.as_nanos() as f64 / avg_initial.as_nanos() as f64;

        FragmentationResult {
            initial_alloc_time: avg_initial,
            fragmented_alloc_time: avg_fragmented,
            fragmentation_overhead,
            num_allocations,
            allocation_size,
        }
    }

    /// Benchmark memory pool performance
    pub fn benchmark_memory_pool(&self, block_size: usize) -> MemoryPoolResult {
        let pool_size = 100;

        // Create a simple pool
        let mut pool: Vec<Vec<u8>> = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            pool.push(vec![0u8; block_size]);
        }

        // Benchmark pool allocation vs regular allocation
        let mut pool_times = Vec::with_capacity(self.config.iterations);
        let mut regular_times = Vec::with_capacity(self.config.iterations);

        for i in 0..self.config.iterations {
            // Pool allocation (reuse)
            let pool_start = Instant::now();
            let block = pool.pop().unwrap();
            std::hint::black_box(&block);
            pool.push(block);
            pool_times.push(pool_start.elapsed());

            // Regular allocation
            let regular_start = Instant::now();
            let block: Vec<u8> = vec![0u8; block_size];
            std::hint::black_box(&block);
            drop(block);
            regular_times.push(regular_start.elapsed());
        }

        let pool_avg = Duration::from_nanos(
            (pool_times.iter().map(|d| d.as_nanos()).sum::<u128>() / self.config.iterations as u128) as u64
        );
        let regular_avg = Duration::from_nanos(
            (regular_times.iter().map(|d| d.as_nanos()).sum::<u128>() / self.config.iterations as u128) as u64
        );

        let speedup = regular_avg.as_nanos() as f64 / pool_avg.as_nanos() as f64;

        MemoryPoolResult {
            block_size,
            pool_alloc_time: pool_avg,
            regular_alloc_time: regular_avg,
            speedup,
        }
    }
}

// ============ Result Types ============

/// All memory benchmark results
#[derive(Debug)]
pub struct MemoryResults {
    pub allocation_results: Vec<AllocationResult>,
    pub bandwidth_results: Vec<BandwidthResult>,
    pub fragmentation_result: Option<FragmentationResult>,
    pub pool_results: Vec<MemoryPoolResult>,
}

impl MemoryResults {
    /// Generate summary report
    pub fn summary(&self) -> String {
        let mut s = String::new();
        s.push_str("Memory Benchmark Results\n");
        s.push_str(&format!("{}\n\n", "=".repeat(50)));

        s.push_str("Allocation Performance:\n");
        for result in &self.allocation_results {
            s.push_str(&format!(
                "  {} bytes: alloc={:.2?}, dealloc={:.2?}, throughput={:.2} MB/s\n",
                result.size,
                result.alloc_mean,
                result.dealloc_mean,
                result.alloc_throughput
            ));
        }

        if !self.bandwidth_results.is_empty() {
            s.push_str("\nBandwidth:\n");
            for result in &self.bandwidth_results {
                s.push_str(&format!(
                    "  {} bytes: read={:.2} GB/s, write={:.2} GB/s, copy={:.2} GB/s\n",
                    result.size,
                    result.read_bandwidth_gbps,
                    result.write_bandwidth_gbps,
                    result.copy_bandwidth_gbps
                ));
            }
        }

        if let Some(ref frag) = self.fragmentation_result {
            s.push_str(&format!(
                "\nFragmentation overhead: {:.2}x slower\n",
                frag.fragmentation_overhead
            ));
        }

        s.push_str("\nMemory Pool Performance:\n");
        for result in &self.pool_results {
            s.push_str(&format!(
                "  {} bytes: {:.2}x speedup with pooling\n",
                result.block_size,
                result.speedup
            ));
        }

        s
    }
}

#[derive(Debug, Clone)]
pub struct AllocationResult {
    pub size: usize,
    pub alloc_mean: Duration,
    pub dealloc_mean: Duration,
    pub alloc_throughput: f64, // MB/s
}

#[derive(Debug, Clone)]
pub struct BandwidthResult {
    pub size: usize,
    pub read_bandwidth_gbps: f64,
    pub write_bandwidth_gbps: f64,
    pub copy_bandwidth_gbps: f64,
}

#[derive(Debug, Clone)]
pub struct FragmentationResult {
    pub initial_alloc_time: Duration,
    pub fragmented_alloc_time: Duration,
    pub fragmentation_overhead: f64,
    pub num_allocations: usize,
    pub allocation_size: usize,
}

#[derive(Debug, Clone)]
pub struct MemoryPoolResult {
    pub block_size: usize,
    pub pool_alloc_time: Duration,
    pub regular_alloc_time: Duration,
    pub speedup: f64,
}

// ============ Tensor Memory Profiler ============

/// Profile memory usage for tensor operations
pub struct TensorMemoryProfiler {
    allocations: Vec<TensorAllocation>,
    peak_memory: usize,
    current_memory: usize,
}

#[derive(Debug, Clone)]
pub struct TensorAllocation {
    pub name: String,
    pub shape: Vec<usize>,
    pub dtype_size: usize,
    pub size_bytes: usize,
    pub timestamp: Instant,
}

impl TensorMemoryProfiler {
    pub fn new() -> Self {
        TensorMemoryProfiler {
            allocations: Vec::new(),
            peak_memory: 0,
            current_memory: 0,
        }
    }

    pub fn record_allocation(&mut self, name: &str, shape: &[usize], dtype_size: usize) {
        let size_bytes: usize = shape.iter().product::<usize>() * dtype_size;

        self.allocations.push(TensorAllocation {
            name: name.to_string(),
            shape: shape.to_vec(),
            dtype_size,
            size_bytes,
            timestamp: Instant::now(),
        });

        self.current_memory += size_bytes;
        self.peak_memory = self.peak_memory.max(self.current_memory);
    }

    pub fn record_deallocation(&mut self, size_bytes: usize) {
        self.current_memory = self.current_memory.saturating_sub(size_bytes);
    }

    pub fn peak_memory(&self) -> usize {
        self.peak_memory
    }

    pub fn current_memory(&self) -> usize {
        self.current_memory
    }

    pub fn report(&self) -> String {
        let mut s = String::new();
        s.push_str("Tensor Memory Profile\n");
        s.push_str(&format!("{}\n\n", "=".repeat(50)));
        s.push_str(&format!("Peak memory: {} MB\n", self.peak_memory / 1024 / 1024));
        s.push_str(&format!("Current memory: {} MB\n", self.current_memory / 1024 / 1024));
        s.push_str(&format!("Total allocations: {}\n\n", self.allocations.len()));

        s.push_str("Top allocations by size:\n");
        let mut sorted: Vec<_> = self.allocations.iter().collect();
        sorted.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));

        for alloc in sorted.iter().take(10) {
            s.push_str(&format!(
                "  {}: {:?} = {} MB\n",
                alloc.name,
                alloc.shape,
                alloc.size_bytes / 1024 / 1024
            ));
        }

        s
    }
}

impl Default for TensorMemoryProfiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_benchmark() {
        let config = MemoryBenchmarkConfig {
            allocation_sizes: vec![1024, 1024 * 1024],
            iterations: 10,
            test_fragmentation: false,
            test_bandwidth: false,
        };

        let bench = MemoryBenchmark::new(config);
        let results = bench.run_all();

        assert!(!results.allocation_results.is_empty());
    }

    #[test]
    fn test_bandwidth_benchmark() {
        let config = MemoryBenchmarkConfig {
            allocation_sizes: vec![1024 * 1024],
            iterations: 5,
            test_bandwidth: true,
            test_fragmentation: false,
        };

        let bench = MemoryBenchmark::new(config);
        let result = bench.benchmark_bandwidth(1024 * 1024);

        assert!(result.read_bandwidth_gbps > 0.0);
    }

    #[test]
    fn test_tensor_memory_profiler() {
        let mut profiler = TensorMemoryProfiler::new();

        profiler.record_allocation("weight", &[768, 768], 4);
        profiler.record_allocation("bias", &[768], 4);

        assert!(profiler.peak_memory() > 0);
    }
}
