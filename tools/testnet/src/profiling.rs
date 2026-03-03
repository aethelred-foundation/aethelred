//! Performance Profiling for Aethelred Testnet
//!
//! Comprehensive profiling capabilities:
//! - Gas usage analysis
//! - Execution time breakdown
//! - Memory consumption tracking
//! - Storage access patterns
//! - Opcode-level profiling
//! - Hot path detection
//! - Optimization suggestions

use std::collections::{HashMap, BTreeMap};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

// ============ Profiling Configuration ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilingConfig {
    /// Enable profiling
    pub enabled: bool,

    /// Collect opcode-level data
    pub opcode_profiling: bool,

    /// Collect memory snapshots
    pub memory_profiling: bool,

    /// Collect storage access patterns
    pub storage_profiling: bool,

    /// Sample rate (1.0 = profile all, 0.1 = 10%)
    pub sample_rate: f64,

    /// Maximum profiles to store
    pub max_profiles: usize,

    /// Aggregate similar profiles
    pub aggregate_similar: bool,

    /// Hot path detection threshold (microseconds)
    pub hot_path_threshold_us: u64,
}

impl Default for ProfilingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            opcode_profiling: true,
            memory_profiling: true,
            storage_profiling: true,
            sample_rate: 1.0,
            max_profiles: 10000,
            aggregate_similar: true,
            hot_path_threshold_us: 1000,
        }
    }
}

// ============ Execution Profile ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionProfile {
    /// Profile ID
    pub id: String,

    /// Transaction hash
    pub tx_hash: String,

    /// Contract address
    pub contract_address: Option<String>,

    /// Function selector
    pub function_selector: Option<String>,

    /// Gas metrics
    pub gas: GasProfile,

    /// Execution time metrics
    pub timing: TimingProfile,

    /// Memory metrics
    pub memory: MemoryProfile,

    /// Storage metrics
    pub storage: StorageProfile,

    /// Call trace
    pub call_trace: Option<CallTrace>,

    /// Opcode breakdown
    pub opcodes: Option<OpcodeProfile>,

    /// Detected hot paths
    pub hot_paths: Vec<HotPath>,

    /// Optimization suggestions
    pub suggestions: Vec<OptimizationSuggestion>,

    /// Profile timestamp
    pub timestamp: u64,

    /// Block number
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasProfile {
    /// Total gas used
    pub total_used: u64,

    /// Gas limit
    pub limit: u64,

    /// Intrinsic gas (base cost)
    pub intrinsic: u64,

    /// Execution gas
    pub execution: u64,

    /// Refund amount
    pub refund: u64,

    /// Gas by category
    pub by_category: HashMap<String, u64>,

    /// Most expensive operations
    pub top_consumers: Vec<GasConsumer>,

    /// Gas price (wei)
    pub gas_price: u64,

    /// Total cost (wei)
    pub total_cost: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasConsumer {
    pub operation: String,
    pub gas_used: u64,
    pub percentage: f64,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingProfile {
    /// Total execution time
    pub total_us: u64,

    /// Time breakdown by phase
    pub by_phase: HashMap<String, u64>,

    /// Time breakdown by call
    pub by_call: Vec<CallTiming>,

    /// Wall clock time
    pub wall_clock_us: u64,

    /// CPU time (if available)
    pub cpu_time_us: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTiming {
    pub call_index: u32,
    pub target: String,
    pub function: Option<String>,
    pub duration_us: u64,
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProfile {
    /// Peak memory usage (bytes)
    pub peak_bytes: u64,

    /// Total memory allocated
    pub total_allocated: u64,

    /// Memory growth pattern
    pub growth_pattern: Vec<MemorySnapshot>,

    /// Memory by call depth
    pub by_depth: HashMap<u32, u64>,

    /// Expansion costs
    pub expansion_costs: Vec<MemoryExpansion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshot {
    pub step: u64,
    pub size_bytes: u64,
    pub opcode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryExpansion {
    pub from_bytes: u64,
    pub to_bytes: u64,
    pub gas_cost: u64,
    pub step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProfile {
    /// Total storage reads
    pub reads: u64,

    /// Total storage writes
    pub writes: u64,

    /// Cold reads (first access)
    pub cold_reads: u64,

    /// Warm reads (subsequent access)
    pub warm_reads: u64,

    /// Unique slots accessed
    pub unique_slots: u64,

    /// Access pattern by slot
    pub slot_access: HashMap<String, SlotAccess>,

    /// Storage gas costs
    pub storage_gas: StorageGas,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotAccess {
    pub slot: String,
    pub reads: u64,
    pub writes: u64,
    pub first_access_step: u64,
    pub was_cold: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageGas {
    pub sload_cold: u64,
    pub sload_warm: u64,
    pub sstore_cold: u64,
    pub sstore_warm: u64,
    pub sstore_refund: u64,
}

// ============ Call Trace ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTrace {
    pub root: CallFrame,
    pub depth: u32,
    pub call_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
    pub index: u32,
    pub call_type: CallType,
    pub from: String,
    pub to: String,
    pub value: String,
    pub gas_provided: u64,
    pub gas_used: u64,
    pub input_size: usize,
    pub output_size: usize,
    pub success: bool,
    pub error: Option<String>,
    pub duration_us: u64,
    pub children: Vec<CallFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CallType {
    Call,
    StaticCall,
    DelegateCall,
    Create,
    Create2,
}

// ============ Opcode Profile ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeProfile {
    /// Total opcodes executed
    pub total_executed: u64,

    /// Execution by opcode
    pub by_opcode: HashMap<String, OpcodeStats>,

    /// Most expensive opcodes
    pub top_expensive: Vec<OpcodeStats>,

    /// Most frequent opcodes
    pub top_frequent: Vec<OpcodeStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeStats {
    pub opcode: String,
    pub count: u64,
    pub total_gas: u64,
    pub avg_gas: f64,
    pub total_time_us: u64,
    pub percentage_gas: f64,
    pub percentage_time: f64,
}

// ============ Hot Paths ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotPath {
    pub name: String,
    pub location: String,
    pub execution_time_us: u64,
    pub gas_used: u64,
    pub frequency: u64,
    pub percentage_of_total: f64,
    pub optimization_potential: OptimizationPotential,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OptimizationPotential {
    Low,
    Medium,
    High,
    Critical,
}

// ============ Optimization Suggestions ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSuggestion {
    pub category: SuggestionCategory,
    pub severity: SuggestionSeverity,
    pub title: String,
    pub description: String,
    pub location: Option<String>,
    pub estimated_savings: Option<EstimatedSavings>,
    pub code_example: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SuggestionCategory {
    GasOptimization,
    StoragePattern,
    MemoryUsage,
    LoopOptimization,
    DataStructure,
    ExternalCalls,
    EventEmission,
    Caching,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SuggestionSeverity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EstimatedSavings {
    pub gas_saved: u64,
    pub percentage: f64,
    pub cost_saved_usd: Option<f64>,
}

// ============ Profiler Engine ============

pub struct AdvancedProfiler {
    config: ProfilingConfig,
    profiles: HashMap<String, ExecutionProfile>,
    aggregated: HashMap<String, AggregatedProfile>,
    current_session: Option<ProfilingSession>,
    metrics: ProfilerMetrics,
}

#[derive(Debug, Clone)]
pub struct ProfilingSession {
    pub id: String,
    pub started_at: Instant,
    pub tx_hash: String,
    pub steps: Vec<ExecutionStep>,
    pub memory_snapshots: Vec<MemorySnapshot>,
    pub storage_accesses: Vec<StorageAccess>,
}

#[derive(Debug, Clone)]
pub struct ExecutionStep {
    pub index: u64,
    pub opcode: String,
    pub gas_cost: u64,
    pub gas_remaining: u64,
    pub pc: u64,
    pub stack_size: usize,
    pub memory_size: u64,
    pub depth: u32,
    pub duration_ns: u64,
}

#[derive(Debug, Clone)]
pub struct StorageAccess {
    pub step: u64,
    pub slot: String,
    pub access_type: StorageAccessType,
    pub value: Option<String>,
    pub gas_cost: u64,
}

#[derive(Debug, Clone)]
pub enum StorageAccessType {
    Read,
    Write,
    ColdRead,
    WarmRead,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedProfile {
    pub contract_address: String,
    pub function_selector: Option<String>,
    pub sample_count: u64,
    pub avg_gas: f64,
    pub min_gas: u64,
    pub max_gas: u64,
    pub avg_time_us: f64,
    pub min_time_us: u64,
    pub max_time_us: u64,
    pub total_invocations: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProfilerMetrics {
    pub total_profiles: u64,
    pub profiles_sampled: u64,
    pub profiles_skipped: u64,
    pub total_gas_profiled: u128,
    pub total_time_profiled_us: u128,
    pub suggestions_generated: u64,
}

impl AdvancedProfiler {
    pub fn new(config: ProfilingConfig) -> Self {
        Self {
            config,
            profiles: HashMap::new(),
            aggregated: HashMap::new(),
            current_session: None,
            metrics: ProfilerMetrics::default(),
        }
    }

    /// Start profiling a transaction
    pub fn start_session(&mut self, tx_hash: &str) -> String {
        let session_id = format!("prof_{}", generate_id());

        self.current_session = Some(ProfilingSession {
            id: session_id.clone(),
            started_at: Instant::now(),
            tx_hash: tx_hash.to_string(),
            steps: Vec::new(),
            memory_snapshots: Vec::new(),
            storage_accesses: Vec::new(),
        });

        session_id
    }

    /// Record an execution step
    pub fn record_step(&mut self, step: ExecutionStep) {
        if let Some(ref mut session) = self.current_session {
            session.steps.push(step);
        }
    }

    /// Record a memory snapshot
    pub fn record_memory(&mut self, snapshot: MemorySnapshot) {
        if let Some(ref mut session) = self.current_session {
            session.memory_snapshots.push(snapshot);
        }
    }

    /// Record a storage access
    pub fn record_storage(&mut self, access: StorageAccess) {
        if let Some(ref mut session) = self.current_session {
            session.storage_accesses.push(access);
        }
    }

    /// End profiling session and generate profile
    pub fn end_session(&mut self) -> Option<ExecutionProfile> {
        let session = self.current_session.take()?;
        let profile = self.generate_profile(session);

        let profile_id = profile.id.clone();
        self.profiles.insert(profile_id, profile.clone());
        self.metrics.total_profiles += 1;

        // Aggregate
        if self.config.aggregate_similar {
            self.aggregate_profile(&profile);
        }

        // Cleanup old profiles
        if self.profiles.len() > self.config.max_profiles {
            self.cleanup_old_profiles();
        }

        Some(profile)
    }

    fn generate_profile(&mut self, session: ProfilingSession) -> ExecutionProfile {
        let total_duration = session.started_at.elapsed();

        // Calculate gas profile
        let gas = self.calculate_gas_profile(&session);

        // Calculate timing profile
        let timing = self.calculate_timing_profile(&session, total_duration);

        // Calculate memory profile
        let memory = self.calculate_memory_profile(&session);

        // Calculate storage profile
        let storage = self.calculate_storage_profile(&session);

        // Calculate opcode profile
        let opcodes = if self.config.opcode_profiling {
            Some(self.calculate_opcode_profile(&session))
        } else {
            None
        };

        // Detect hot paths
        let hot_paths = self.detect_hot_paths(&session);

        // Generate suggestions
        let suggestions = self.generate_suggestions(&gas, &storage, &memory, &hot_paths);

        self.metrics.suggestions_generated += suggestions.len() as u64;

        ExecutionProfile {
            id: session.id,
            tx_hash: session.tx_hash,
            contract_address: None,
            function_selector: None,
            gas,
            timing,
            memory,
            storage,
            call_trace: None,
            opcodes,
            hot_paths,
            suggestions,
            timestamp: current_timestamp(),
            block_number: 0,
        }
    }

    fn calculate_gas_profile(&self, session: &ProfilingSession) -> GasProfile {
        let mut total_used = 0u64;
        let mut by_category: HashMap<String, u64> = HashMap::new();
        let mut opcode_gas: HashMap<String, u64> = HashMap::new();

        for step in &session.steps {
            total_used += step.gas_cost;

            let category = categorize_opcode(&step.opcode);
            *by_category.entry(category).or_insert(0) += step.gas_cost;
            *opcode_gas.entry(step.opcode.clone()).or_insert(0) += step.gas_cost;
        }

        let mut top_consumers: Vec<GasConsumer> = opcode_gas.iter()
            .map(|(op, gas)| GasConsumer {
                operation: op.clone(),
                gas_used: *gas,
                percentage: (*gas as f64 / total_used.max(1) as f64) * 100.0,
                count: session.steps.iter().filter(|s| &s.opcode == op).count() as u64,
            })
            .collect();

        top_consumers.sort_by(|a, b| b.gas_used.cmp(&a.gas_used));
        top_consumers.truncate(10);

        GasProfile {
            total_used,
            limit: 0,
            intrinsic: 21000,
            execution: total_used.saturating_sub(21000),
            refund: 0,
            by_category,
            top_consumers,
            gas_price: 1_000_000_000, // 1 gwei
            total_cost: total_used as u128 * 1_000_000_000,
        }
    }

    fn calculate_timing_profile(&self, session: &ProfilingSession, total_duration: Duration) -> TimingProfile {
        let mut by_phase: HashMap<String, u64> = HashMap::new();
        let mut by_call = Vec::new();

        let total_us = total_duration.as_micros() as u64;

        // Calculate time by opcode category
        for step in &session.steps {
            let category = categorize_opcode(&step.opcode);
            *by_phase.entry(category).or_insert(0) += step.duration_ns / 1000;
        }

        TimingProfile {
            total_us,
            by_phase,
            by_call,
            wall_clock_us: total_us,
            cpu_time_us: Some(total_us),
        }
    }

    fn calculate_memory_profile(&self, session: &ProfilingSession) -> MemoryProfile {
        let peak_bytes = session.memory_snapshots.iter()
            .map(|s| s.size_bytes)
            .max()
            .unwrap_or(0);

        let total_allocated = session.steps.iter()
            .filter(|s| s.opcode == "MSTORE" || s.opcode == "MSTORE8")
            .count() as u64 * 32;

        let by_depth: HashMap<u32, u64> = HashMap::new();
        let expansion_costs = Vec::new();

        MemoryProfile {
            peak_bytes,
            total_allocated,
            growth_pattern: session.memory_snapshots.clone(),
            by_depth,
            expansion_costs,
        }
    }

    fn calculate_storage_profile(&self, session: &ProfilingSession) -> StorageProfile {
        let mut reads = 0u64;
        let mut writes = 0u64;
        let mut cold_reads = 0u64;
        let mut warm_reads = 0u64;
        let mut slot_access: HashMap<String, SlotAccess> = HashMap::new();

        for access in &session.storage_accesses {
            match access.access_type {
                StorageAccessType::Read => reads += 1,
                StorageAccessType::Write => writes += 1,
                StorageAccessType::ColdRead => {
                    reads += 1;
                    cold_reads += 1;
                }
                StorageAccessType::WarmRead => {
                    reads += 1;
                    warm_reads += 1;
                }
            }

            let entry = slot_access.entry(access.slot.clone()).or_insert(SlotAccess {
                slot: access.slot.clone(),
                reads: 0,
                writes: 0,
                first_access_step: access.step,
                was_cold: matches!(access.access_type, StorageAccessType::ColdRead),
            });

            match access.access_type {
                StorageAccessType::Read | StorageAccessType::ColdRead | StorageAccessType::WarmRead => {
                    entry.reads += 1;
                }
                StorageAccessType::Write => {
                    entry.writes += 1;
                }
            }
        }

        StorageProfile {
            reads,
            writes,
            cold_reads,
            warm_reads,
            unique_slots: slot_access.len() as u64,
            slot_access,
            storage_gas: StorageGas {
                sload_cold: cold_reads * 2100,
                sload_warm: warm_reads * 100,
                sstore_cold: 0,
                sstore_warm: 0,
                sstore_refund: 0,
            },
        }
    }

    fn calculate_opcode_profile(&self, session: &ProfilingSession) -> OpcodeProfile {
        let mut by_opcode: HashMap<String, OpcodeStats> = HashMap::new();

        for step in &session.steps {
            let entry = by_opcode.entry(step.opcode.clone()).or_insert(OpcodeStats {
                opcode: step.opcode.clone(),
                count: 0,
                total_gas: 0,
                avg_gas: 0.0,
                total_time_us: 0,
                percentage_gas: 0.0,
                percentage_time: 0.0,
            });

            entry.count += 1;
            entry.total_gas += step.gas_cost;
            entry.total_time_us += step.duration_ns / 1000;
        }

        let total_gas: u64 = by_opcode.values().map(|s| s.total_gas).sum();
        let total_time: u64 = by_opcode.values().map(|s| s.total_time_us).sum();

        for stats in by_opcode.values_mut() {
            stats.avg_gas = stats.total_gas as f64 / stats.count.max(1) as f64;
            stats.percentage_gas = (stats.total_gas as f64 / total_gas.max(1) as f64) * 100.0;
            stats.percentage_time = (stats.total_time_us as f64 / total_time.max(1) as f64) * 100.0;
        }

        let mut top_expensive: Vec<OpcodeStats> = by_opcode.values().cloned().collect();
        top_expensive.sort_by(|a, b| b.total_gas.cmp(&a.total_gas));
        top_expensive.truncate(10);

        let mut top_frequent: Vec<OpcodeStats> = by_opcode.values().cloned().collect();
        top_frequent.sort_by(|a, b| b.count.cmp(&a.count));
        top_frequent.truncate(10);

        OpcodeProfile {
            total_executed: session.steps.len() as u64,
            by_opcode,
            top_expensive,
            top_frequent,
        }
    }

    fn detect_hot_paths(&self, session: &ProfilingSession) -> Vec<HotPath> {
        let mut hot_paths = Vec::new();

        // Detect loops (simplified)
        let mut pc_counts: HashMap<u64, u64> = HashMap::new();
        for step in &session.steps {
            *pc_counts.entry(step.pc).or_insert(0) += 1;
        }

        for (pc, count) in pc_counts {
            if count > 10 {
                hot_paths.push(HotPath {
                    name: format!("Loop at PC {}", pc),
                    location: format!("0x{:x}", pc),
                    execution_time_us: 0,
                    gas_used: 0,
                    frequency: count,
                    percentage_of_total: 0.0,
                    optimization_potential: if count > 100 {
                        OptimizationPotential::High
                    } else if count > 50 {
                        OptimizationPotential::Medium
                    } else {
                        OptimizationPotential::Low
                    },
                });
            }
        }

        hot_paths
    }

    fn generate_suggestions(
        &self,
        gas: &GasProfile,
        storage: &StorageProfile,
        memory: &MemoryProfile,
        hot_paths: &[HotPath],
    ) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();

        // Storage optimization suggestions
        if storage.cold_reads > storage.warm_reads {
            suggestions.push(OptimizationSuggestion {
                category: SuggestionCategory::StoragePattern,
                severity: SuggestionSeverity::Medium,
                title: "High cold storage reads".to_string(),
                description: "Consider caching frequently accessed storage slots in memory".to_string(),
                location: None,
                estimated_savings: Some(EstimatedSavings {
                    gas_saved: storage.cold_reads * 2000,
                    percentage: 10.0,
                    cost_saved_usd: None,
                }),
                code_example: Some("uint256 cached = storageVar; // Cache at function start".to_string()),
            });
        }

        // Memory optimization suggestions
        if memory.peak_bytes > 1024 * 10 {
            suggestions.push(OptimizationSuggestion {
                category: SuggestionCategory::MemoryUsage,
                severity: SuggestionSeverity::Low,
                title: "High memory usage".to_string(),
                description: "Consider using bytes32 arrays instead of dynamic memory".to_string(),
                location: None,
                estimated_savings: None,
                code_example: None,
            });
        }

        // Loop optimization suggestions
        for hot_path in hot_paths {
            if matches!(hot_path.optimization_potential, OptimizationPotential::High | OptimizationPotential::Critical) {
                suggestions.push(OptimizationSuggestion {
                    category: SuggestionCategory::LoopOptimization,
                    severity: SuggestionSeverity::High,
                    title: format!("Hot loop detected: {}", hot_path.name),
                    description: "Consider reducing iterations or moving invariants outside the loop".to_string(),
                    location: Some(hot_path.location.clone()),
                    estimated_savings: Some(EstimatedSavings {
                        gas_saved: hot_path.gas_used / 2,
                        percentage: 15.0,
                        cost_saved_usd: None,
                    }),
                    code_example: None,
                });
            }
        }

        // Gas optimization by opcode
        for consumer in &gas.top_consumers {
            if consumer.opcode == "SSTORE" && consumer.percentage > 30.0 {
                suggestions.push(OptimizationSuggestion {
                    category: SuggestionCategory::GasOptimization,
                    severity: SuggestionSeverity::High,
                    title: "High SSTORE costs".to_string(),
                    description: "SSTORE operations consume significant gas. Consider batching updates.".to_string(),
                    location: None,
                    estimated_savings: Some(EstimatedSavings {
                        gas_saved: consumer.gas_used / 3,
                        percentage: 10.0,
                        cost_saved_usd: None,
                    }),
                    code_example: None,
                });
            }
        }

        suggestions
    }

    fn aggregate_profile(&mut self, profile: &ExecutionProfile) {
        let key = format!(
            "{}:{}",
            profile.contract_address.as_deref().unwrap_or("unknown"),
            profile.function_selector.as_deref().unwrap_or("unknown")
        );

        let entry = self.aggregated.entry(key.clone()).or_insert(AggregatedProfile {
            contract_address: profile.contract_address.clone().unwrap_or_default(),
            function_selector: profile.function_selector.clone(),
            sample_count: 0,
            avg_gas: 0.0,
            min_gas: u64::MAX,
            max_gas: 0,
            avg_time_us: 0.0,
            min_time_us: u64::MAX,
            max_time_us: 0,
            total_invocations: 0,
        });

        entry.sample_count += 1;
        entry.total_invocations += 1;

        // Update gas stats
        let gas = profile.gas.total_used;
        entry.avg_gas = ((entry.avg_gas * (entry.sample_count - 1) as f64) + gas as f64)
            / entry.sample_count as f64;
        entry.min_gas = entry.min_gas.min(gas);
        entry.max_gas = entry.max_gas.max(gas);

        // Update time stats
        let time = profile.timing.total_us;
        entry.avg_time_us = ((entry.avg_time_us * (entry.sample_count - 1) as f64) + time as f64)
            / entry.sample_count as f64;
        entry.min_time_us = entry.min_time_us.min(time);
        entry.max_time_us = entry.max_time_us.max(time);
    }

    fn cleanup_old_profiles(&mut self) {
        // Remove oldest profiles
        if self.profiles.len() > self.config.max_profiles {
            let excess = self.profiles.len() - self.config.max_profiles;
            let mut profiles: Vec<_> = self.profiles.iter().collect();
            profiles.sort_by_key(|(_, p)| p.timestamp);

            for (id, _) in profiles.into_iter().take(excess) {
                self.profiles.remove(id);
            }
        }
    }

    /// Get a profile by ID
    pub fn get_profile(&self, id: &str) -> Option<&ExecutionProfile> {
        self.profiles.get(id)
    }

    /// Get profile by transaction hash
    pub fn get_profile_by_tx(&self, tx_hash: &str) -> Option<&ExecutionProfile> {
        self.profiles.values().find(|p| p.tx_hash == tx_hash)
    }

    /// Get aggregated profiles
    pub fn aggregated_profiles(&self) -> &HashMap<String, AggregatedProfile> {
        &self.aggregated
    }

    /// Get metrics
    pub fn metrics(&self) -> &ProfilerMetrics {
        &self.metrics
    }

    /// Compare two profiles
    pub fn compare_profiles(&self, id1: &str, id2: &str) -> Option<ProfileComparison> {
        let p1 = self.profiles.get(id1)?;
        let p2 = self.profiles.get(id2)?;

        Some(ProfileComparison {
            profile1_id: id1.to_string(),
            profile2_id: id2.to_string(),
            gas_diff: p2.gas.total_used as i64 - p1.gas.total_used as i64,
            gas_diff_percentage: ((p2.gas.total_used as f64 - p1.gas.total_used as f64)
                / p1.gas.total_used.max(1) as f64) * 100.0,
            time_diff_us: p2.timing.total_us as i64 - p1.timing.total_us as i64,
            time_diff_percentage: ((p2.timing.total_us as f64 - p1.timing.total_us as f64)
                / p1.timing.total_us.max(1) as f64) * 100.0,
            memory_diff: p2.memory.peak_bytes as i64 - p1.memory.peak_bytes as i64,
            storage_reads_diff: p2.storage.reads as i64 - p1.storage.reads as i64,
            storage_writes_diff: p2.storage.writes as i64 - p1.storage.writes as i64,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileComparison {
    pub profile1_id: String,
    pub profile2_id: String,
    pub gas_diff: i64,
    pub gas_diff_percentage: f64,
    pub time_diff_us: i64,
    pub time_diff_percentage: f64,
    pub memory_diff: i64,
    pub storage_reads_diff: i64,
    pub storage_writes_diff: i64,
}

// ============ Helper Functions ============

fn categorize_opcode(opcode: &str) -> String {
    match opcode {
        "ADD" | "SUB" | "MUL" | "DIV" | "MOD" | "EXP" => "Arithmetic".to_string(),
        "LT" | "GT" | "EQ" | "ISZERO" | "AND" | "OR" | "XOR" | "NOT" => "Logic".to_string(),
        "SHA3" | "KECCAK256" => "Hashing".to_string(),
        "SLOAD" | "SSTORE" => "Storage".to_string(),
        "MLOAD" | "MSTORE" | "MSTORE8" => "Memory".to_string(),
        "CALL" | "STATICCALL" | "DELEGATECALL" | "CALLCODE" => "External".to_string(),
        "CREATE" | "CREATE2" => "Contract".to_string(),
        "LOG0" | "LOG1" | "LOG2" | "LOG3" | "LOG4" => "Logging".to_string(),
        "JUMP" | "JUMPI" | "JUMPDEST" => "Control".to_string(),
        _ => "Other".to_string(),
    }
}

fn generate_id() -> String {
    use rand::Rng;
    let random: u64 = rand::thread_rng().gen();
    format!("{:x}", random)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profiler_creation() {
        let config = ProfilingConfig::default();
        let profiler = AdvancedProfiler::new(config);

        assert_eq!(profiler.metrics().total_profiles, 0);
    }

    #[test]
    fn test_profiling_session() {
        let config = ProfilingConfig::default();
        let mut profiler = AdvancedProfiler::new(config);

        let session_id = profiler.start_session("0xabc123");

        profiler.record_step(ExecutionStep {
            index: 0,
            opcode: "PUSH1".to_string(),
            gas_cost: 3,
            gas_remaining: 1000000,
            pc: 0,
            stack_size: 0,
            memory_size: 0,
            depth: 1,
            duration_ns: 100,
        });

        profiler.record_step(ExecutionStep {
            index: 1,
            opcode: "SLOAD".to_string(),
            gas_cost: 2100,
            gas_remaining: 999997,
            pc: 2,
            stack_size: 1,
            memory_size: 0,
            depth: 1,
            duration_ns: 500,
        });

        let profile = profiler.end_session();
        assert!(profile.is_some());

        let profile = profile.unwrap();
        assert_eq!(profile.tx_hash, "0xabc123");
        assert!(profile.gas.total_used > 0);
    }

    #[test]
    fn test_opcode_categorization() {
        assert_eq!(categorize_opcode("ADD"), "Arithmetic");
        assert_eq!(categorize_opcode("SLOAD"), "Storage");
        assert_eq!(categorize_opcode("CALL"), "External");
    }
}
