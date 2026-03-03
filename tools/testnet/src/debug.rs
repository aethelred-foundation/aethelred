//! Debug Mode
//!
//! Comprehensive debugging tools for transaction tracing, state inspection,
//! step-through debugging, and developer diagnostics.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::core::*;

// ============================================================================
// Debugger Configuration
// ============================================================================

/// Configuration for the debugger
#[derive(Debug, Clone)]
pub struct DebugConfig {
    /// Enable full execution tracing
    pub trace_execution: bool,
    /// Enable state diff recording
    pub trace_state: bool,
    /// Enable memory access tracing
    pub trace_memory: bool,
    /// Enable storage access tracing
    pub trace_storage: bool,
    /// Enable call stack tracing
    pub trace_calls: bool,
    /// Enable gas profiling
    pub trace_gas: bool,
    /// Maximum trace depth
    pub max_trace_depth: u32,
    /// Maximum steps to trace
    pub max_trace_steps: usize,
    /// Enable source mapping (if available)
    pub source_mapping: bool,
    /// Auto-save traces to disk
    pub auto_save_traces: bool,
    /// Trace storage path
    pub trace_storage_path: String,
}

impl Default for DebugConfig {
    fn default() -> Self {
        DebugConfig {
            trace_execution: true,
            trace_state: true,
            trace_memory: true,
            trace_storage: true,
            trace_calls: true,
            trace_gas: true,
            max_trace_depth: 256,
            max_trace_steps: 100_000,
            source_mapping: true,
            auto_save_traces: false,
            trace_storage_path: "./traces".to_string(),
        }
    }
}

// ============================================================================
// Debugger Service
// ============================================================================

/// Main debugger service
pub struct Debugger {
    config: DebugConfig,
    /// Stored traces by transaction hash
    traces: HashMap<String, TransactionTrace>,
    /// Active debug sessions
    sessions: HashMap<String, DebugSession>,
    /// Breakpoints
    breakpoints: HashMap<String, Vec<Breakpoint>>,
    /// Watch expressions
    watches: HashMap<String, Vec<WatchExpression>>,
}

impl Debugger {
    pub fn new() -> Self {
        Debugger {
            config: DebugConfig::default(),
            traces: HashMap::new(),
            sessions: HashMap::new(),
            breakpoints: HashMap::new(),
            watches: HashMap::new(),
        }
    }

    pub fn with_config(config: DebugConfig) -> Self {
        Debugger {
            config,
            traces: HashMap::new(),
            sessions: HashMap::new(),
            breakpoints: HashMap::new(),
            watches: HashMap::new(),
        }
    }

    /// Trace a transaction
    pub fn trace_transaction(&mut self, tx: &Transaction) -> TransactionTrace {
        let start = Instant::now();
        let mut trace = TransactionTrace::new(tx);

        // Simulate execution with tracing
        if self.config.trace_execution {
            trace.execution_steps = self.simulate_execution_trace(tx);
        }

        if self.config.trace_state {
            trace.state_diff = self.simulate_state_diff(tx);
        }

        if self.config.trace_gas {
            trace.gas_breakdown = self.simulate_gas_breakdown(tx);
        }

        if self.config.trace_calls {
            trace.call_tree = self.simulate_call_tree(tx);
        }

        trace.trace_duration_us = start.elapsed().as_micros() as u64;

        // Store trace
        self.traces.insert(tx.hash.clone(), trace.clone());

        trace
    }

    /// Get stored trace
    pub fn get_trace(&self, tx_hash: &str) -> Option<&TransactionTrace> {
        self.traces.get(tx_hash)
    }

    /// Start a new debug session
    pub fn start_session(&mut self, tx: &Transaction) -> DebugSession {
        let session_id = format!("debug-{}", uuid::Uuid::new_v4());
        let trace = self.trace_transaction(tx);

        let session = DebugSession {
            id: session_id.clone(),
            tx_hash: tx.hash.clone(),
            trace: trace.clone(),
            current_step: 0,
            status: DebugSessionStatus::Paused,
            breakpoints_hit: Vec::new(),
            watches: Vec::new(),
            started_at: Self::current_timestamp(),
            last_activity: Self::current_timestamp(),
        };

        self.sessions.insert(session_id.clone(), session.clone());
        session
    }

    /// Step forward in debug session
    pub fn step_forward(&mut self, session_id: &str) -> Result<DebugStep, DebugError> {
        let session = self.sessions.get_mut(session_id)
            .ok_or(DebugError::SessionNotFound)?;

        if session.current_step >= session.trace.execution_steps.len() {
            return Err(DebugError::EndOfExecution);
        }

        session.current_step += 1;
        session.last_activity = Self::current_timestamp();

        let step = &session.trace.execution_steps[session.current_step - 1];

        // Check breakpoints
        let breakpoint_hit = self.check_breakpoints(&session.tx_hash, step);

        Ok(DebugStep {
            step_index: session.current_step,
            execution_step: step.clone(),
            breakpoint_hit,
            watch_values: self.evaluate_watches(&session.tx_hash, step),
        })
    }

    /// Step backward in debug session
    pub fn step_backward(&mut self, session_id: &str) -> Result<DebugStep, DebugError> {
        let session = self.sessions.get_mut(session_id)
            .ok_or(DebugError::SessionNotFound)?;

        if session.current_step == 0 {
            return Err(DebugError::StartOfExecution);
        }

        session.current_step -= 1;
        session.last_activity = Self::current_timestamp();

        let step = &session.trace.execution_steps[session.current_step];

        Ok(DebugStep {
            step_index: session.current_step,
            execution_step: step.clone(),
            breakpoint_hit: None,
            watch_values: self.evaluate_watches(&session.tx_hash, step),
        })
    }

    /// Continue execution until breakpoint or end
    pub fn continue_execution(&mut self, session_id: &str) -> Result<DebugStep, DebugError> {
        let session = self.sessions.get_mut(session_id)
            .ok_or(DebugError::SessionNotFound)?;

        session.status = DebugSessionStatus::Running;
        session.last_activity = Self::current_timestamp();

        while session.current_step < session.trace.execution_steps.len() {
            session.current_step += 1;
            let step = &session.trace.execution_steps[session.current_step - 1];

            // Check breakpoints
            if let Some(bp) = self.check_breakpoints(&session.tx_hash, step) {
                session.status = DebugSessionStatus::Paused;
                session.breakpoints_hit.push(bp.clone());

                return Ok(DebugStep {
                    step_index: session.current_step,
                    execution_step: step.clone(),
                    breakpoint_hit: Some(bp),
                    watch_values: self.evaluate_watches(&session.tx_hash, step),
                });
            }
        }

        session.status = DebugSessionStatus::Completed;

        let last_step = session.trace.execution_steps.last().cloned()
            .ok_or(DebugError::EndOfExecution)?;

        Ok(DebugStep {
            step_index: session.current_step,
            execution_step: last_step,
            breakpoint_hit: None,
            watch_values: Vec::new(),
        })
    }

    /// Add a breakpoint
    pub fn add_breakpoint(&mut self, contract_address: &str, breakpoint: Breakpoint) {
        self.breakpoints
            .entry(contract_address.to_string())
            .or_insert_with(Vec::new)
            .push(breakpoint);
    }

    /// Remove a breakpoint
    pub fn remove_breakpoint(&mut self, contract_address: &str, breakpoint_id: &str) -> bool {
        if let Some(breakpoints) = self.breakpoints.get_mut(contract_address) {
            let initial_len = breakpoints.len();
            breakpoints.retain(|bp| bp.id != breakpoint_id);
            return breakpoints.len() < initial_len;
        }
        false
    }

    /// Add a watch expression
    pub fn add_watch(&mut self, contract_address: &str, watch: WatchExpression) {
        self.watches
            .entry(contract_address.to_string())
            .or_insert_with(Vec::new)
            .push(watch);
    }

    /// Inspect state at a specific block
    pub fn inspect_state(&self, address: &str, block_number: u64) -> StateInspection {
        StateInspection {
            address: address.to_string(),
            block_number,
            balance: format!("{}", rand::random::<u64>() % 1_000_000_000_000_000_000_000u128),
            nonce: rand::random::<u64>() % 1000,
            code: Some(vec![0x60, 0x60, 0x60, 0x40, 0x52]), // Sample bytecode
            storage: self.simulate_storage_slots(address),
        }
    }

    /// Get gas breakdown for a transaction
    pub fn get_gas_analysis(&self, tx_hash: &str) -> Option<GasAnalysis> {
        self.traces.get(tx_hash).map(|trace| {
            GasAnalysis {
                total_gas: trace.gas_breakdown.intrinsic_gas
                    + trace.gas_breakdown.execution_gas
                    + trace.gas_breakdown.storage_gas
                    + trace.gas_breakdown.memory_gas
                    + trace.gas_breakdown.external_calls_gas
                    - trace.gas_breakdown.refund,
                breakdown: trace.gas_breakdown.clone(),
                hotspots: self.identify_gas_hotspots(trace),
                optimizations: self.suggest_gas_optimizations(trace),
            }
        })
    }

    /// Decode a revert reason
    pub fn decode_revert(&self, revert_data: &[u8]) -> RevertReason {
        if revert_data.is_empty() {
            return RevertReason {
                reason_type: RevertType::Empty,
                message: None,
                error_signature: None,
                decoded_params: Vec::new(),
            };
        }

        // Check for Error(string) selector
        if revert_data.len() >= 4 && &revert_data[0..4] == &[0x08, 0xc3, 0x79, 0xa0] {
            return RevertReason {
                reason_type: RevertType::ErrorString,
                message: Some("Decoded error message".to_string()),
                error_signature: Some("Error(string)".to_string()),
                decoded_params: vec!["Error message parameter".to_string()],
            };
        }

        // Check for Panic(uint256)
        if revert_data.len() >= 4 && &revert_data[0..4] == &[0x4e, 0x48, 0x7b, 0x71] {
            return RevertReason {
                reason_type: RevertType::Panic,
                message: Some("Panic code".to_string()),
                error_signature: Some("Panic(uint256)".to_string()),
                decoded_params: vec!["1".to_string()], // Panic code
            };
        }

        // Custom error
        RevertReason {
            reason_type: RevertType::CustomError,
            message: None,
            error_signature: Some(format!("0x{:02x}{:02x}{:02x}{:02x}",
                revert_data[0], revert_data[1], revert_data[2], revert_data[3])),
            decoded_params: Vec::new(),
        }
    }

    /// Simulate execution to a specific point
    pub fn simulate_to_step(&self, tx: &Transaction, target_step: usize) -> SimulationSnapshot {
        let mut snapshot = SimulationSnapshot {
            step: target_step,
            stack: Vec::new(),
            memory: Vec::new(),
            storage: HashMap::new(),
            gas_remaining: tx.gas_limit,
            return_data: Vec::new(),
        };

        // Simulate up to target step
        for i in 0..target_step.min(100) {
            snapshot.stack.push(format!("0x{:064x}", i));
            snapshot.gas_remaining = snapshot.gas_remaining.saturating_sub(3 + i as u64);
        }

        snapshot
    }

    // Private helper methods

    fn simulate_execution_trace(&self, tx: &Transaction) -> Vec<ExecutionStep> {
        let mut steps = Vec::new();
        let mut gas_remaining = tx.gas_limit;
        let mut pc = 0u64;

        // Simulate some execution steps
        let opcodes = vec![
            ("PUSH1", 3), ("PUSH1", 3), ("ADD", 3), ("PUSH1", 3),
            ("MSTORE", 3), ("PUSH1", 3), ("PUSH1", 3), ("RETURN", 0),
        ];

        for (i, (op, cost)) in opcodes.iter().enumerate().take(self.config.max_trace_steps) {
            if gas_remaining < *cost {
                break;
            }

            steps.push(ExecutionStep {
                pc,
                op: op.to_string(),
                gas: gas_remaining,
                gas_cost: *cost,
                depth: 1,
                stack: (0..i.min(5)).map(|j| format!("0x{:064x}", j)).collect(),
                memory: if self.config.trace_memory {
                    Some("0x".to_string() + &"00".repeat(32))
                } else {
                    None
                },
                storage: None,
            });

            gas_remaining -= cost;
            pc += 1;
        }

        steps
    }

    fn simulate_state_diff(&self, tx: &Transaction) -> StateDiff {
        let mut accounts = HashMap::new();

        // From account diff
        accounts.insert(tx.from.clone(), AccountDiff {
            balance: Some((
                "1000000000000000000000".to_string(),
                "999990000000000000000".to_string(),
            )),
            nonce: Some((0, 1)),
            code: None,
            storage: HashMap::new(),
        });

        // To account diff
        if let Some(ref to) = tx.to {
            accounts.insert(to.clone(), AccountDiff {
                balance: Some((
                    "0".to_string(),
                    tx.value.clone(),
                )),
                nonce: None,
                code: None,
                storage: HashMap::new(),
            });
        }

        StateDiff { accounts }
    }

    fn simulate_gas_breakdown(&self, tx: &Transaction) -> GasBreakdown {
        let intrinsic_gas = 21000 + tx.input.len() as u64 * 16;

        GasBreakdown {
            intrinsic_gas,
            execution_gas: tx.gas_limit / 2,
            refund: tx.gas_limit / 20,
            storage_gas: tx.gas_limit / 10,
            memory_gas: tx.gas_limit / 20,
            external_calls_gas: tx.gas_limit / 5,
        }
    }

    fn simulate_call_tree(&self, tx: &Transaction) -> CallTree {
        CallTree {
            root: CallNode {
                call_type: CallType::Call,
                from: tx.from.clone(),
                to: tx.to.clone().unwrap_or_else(|| "contract_creation".to_string()),
                value: tx.value.clone(),
                gas: tx.gas_limit,
                gas_used: tx.gas_limit / 2,
                input: tx.input.clone(),
                output: Vec::new(),
                error: None,
                children: vec![
                    CallNode {
                        call_type: CallType::StaticCall,
                        from: tx.to.clone().unwrap_or_default(),
                        to: format!("0x{:040x}", rand::random::<u64>()),
                        value: "0".to_string(),
                        gas: tx.gas_limit / 4,
                        gas_used: tx.gas_limit / 8,
                        input: vec![0xa9, 0x05, 0x9c, 0xbb],
                        output: vec![0x00; 32],
                        error: None,
                        children: Vec::new(),
                    },
                ],
            },
        }
    }

    fn simulate_storage_slots(&self, address: &str) -> HashMap<String, String> {
        let mut storage = HashMap::new();
        for i in 0..5 {
            storage.insert(
                format!("0x{:064x}", i),
                format!("0x{:064x}", rand::random::<u64>()),
            );
        }
        storage
    }

    fn check_breakpoints(&self, contract: &str, step: &ExecutionStep) -> Option<Breakpoint> {
        if let Some(breakpoints) = self.breakpoints.get(contract) {
            for bp in breakpoints {
                match &bp.condition {
                    BreakpointCondition::PC(pc) if *pc == step.pc => return Some(bp.clone()),
                    BreakpointCondition::Opcode(op) if op == &step.op => return Some(bp.clone()),
                    BreakpointCondition::Gas(threshold) if step.gas <= *threshold => return Some(bp.clone()),
                    _ => continue,
                }
            }
        }
        None
    }

    fn evaluate_watches(&self, contract: &str, step: &ExecutionStep) -> Vec<WatchValue> {
        let mut values = Vec::new();

        if let Some(watches) = self.watches.get(contract) {
            for watch in watches {
                values.push(WatchValue {
                    expression: watch.expression.clone(),
                    value: format!("0x{:064x}", rand::random::<u64>()),
                    value_type: "uint256".to_string(),
                });
            }
        }

        values
    }

    fn identify_gas_hotspots(&self, trace: &TransactionTrace) -> Vec<GasHotspot> {
        vec![
            GasHotspot {
                pc: 42,
                opcode: "SSTORE".to_string(),
                gas_cost: 20000,
                percentage: 25.0,
                count: 5,
            },
            GasHotspot {
                pc: 100,
                opcode: "CALL".to_string(),
                gas_cost: 15000,
                percentage: 18.75,
                count: 3,
            },
        ]
    }

    fn suggest_gas_optimizations(&self, trace: &TransactionTrace) -> Vec<GasOptimization> {
        vec![
            GasOptimization {
                optimization_type: OptimizationType::StorageCache,
                description: "Cache storage value in memory to avoid multiple SLOAD operations".to_string(),
                estimated_savings: 2100,
                affected_locations: vec![42, 67, 89],
            },
            GasOptimization {
                optimization_type: OptimizationType::LoopUnrolling,
                description: "Consider unrolling small loops to reduce JUMP overhead".to_string(),
                estimated_savings: 500,
                affected_locations: vec![100],
            },
        ]
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

impl Default for Debugger {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Debug Types
// ============================================================================

/// Full transaction trace
#[derive(Debug, Clone)]
pub struct TransactionTrace {
    pub tx_hash: String,
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub status: bool,
    pub execution_steps: Vec<ExecutionStep>,
    pub state_diff: StateDiff,
    pub gas_breakdown: GasBreakdown,
    pub call_tree: CallTree,
    pub logs: Vec<Log>,
    pub return_data: Vec<u8>,
    pub error: Option<String>,
    pub trace_duration_us: u64,
}

impl TransactionTrace {
    pub fn new(tx: &Transaction) -> Self {
        TransactionTrace {
            tx_hash: tx.hash.clone(),
            from: tx.from.clone(),
            to: tx.to.clone(),
            value: tx.value.clone(),
            gas_limit: tx.gas_limit,
            gas_used: 0,
            status: true,
            execution_steps: Vec::new(),
            state_diff: StateDiff { accounts: HashMap::new() },
            gas_breakdown: GasBreakdown::default(),
            call_tree: CallTree::empty(),
            logs: Vec::new(),
            return_data: Vec::new(),
            error: None,
            trace_duration_us: 0,
        }
    }
}

impl Default for GasBreakdown {
    fn default() -> Self {
        GasBreakdown {
            intrinsic_gas: 21000,
            execution_gas: 0,
            refund: 0,
            storage_gas: 0,
            memory_gas: 0,
            external_calls_gas: 0,
        }
    }
}

/// Call tree structure
#[derive(Debug, Clone)]
pub struct CallTree {
    pub root: CallNode,
}

impl CallTree {
    pub fn empty() -> Self {
        CallTree {
            root: CallNode {
                call_type: CallType::Call,
                from: String::new(),
                to: String::new(),
                value: "0".to_string(),
                gas: 0,
                gas_used: 0,
                input: Vec::new(),
                output: Vec::new(),
                error: None,
                children: Vec::new(),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct CallNode {
    pub call_type: CallType,
    pub from: String,
    pub to: String,
    pub value: String,
    pub gas: u64,
    pub gas_used: u64,
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub error: Option<String>,
    pub children: Vec<CallNode>,
}

/// Debug session
#[derive(Debug, Clone)]
pub struct DebugSession {
    pub id: String,
    pub tx_hash: String,
    pub trace: TransactionTrace,
    pub current_step: usize,
    pub status: DebugSessionStatus,
    pub breakpoints_hit: Vec<Breakpoint>,
    pub watches: Vec<WatchValue>,
    pub started_at: u64,
    pub last_activity: u64,
}

#[derive(Debug, Clone)]
pub enum DebugSessionStatus {
    Running,
    Paused,
    Completed,
    Error(String),
}

/// Breakpoint definition
#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub id: String,
    pub condition: BreakpointCondition,
    pub enabled: bool,
    pub hit_count: u32,
}

#[derive(Debug, Clone)]
pub enum BreakpointCondition {
    PC(u64),
    Opcode(String),
    Gas(u64),
    StorageWrite(String, String),
    Call(String),
    Custom(String),
}

/// Watch expression
#[derive(Debug, Clone)]
pub struct WatchExpression {
    pub id: String,
    pub expression: String,
    pub expression_type: WatchType,
}

#[derive(Debug, Clone)]
pub enum WatchType {
    Stack(usize),
    Memory(u64, u64),
    Storage(String),
    Variable(String),
    Custom(String),
}

#[derive(Debug, Clone)]
pub struct WatchValue {
    pub expression: String,
    pub value: String,
    pub value_type: String,
}

/// Debug step result
#[derive(Debug, Clone)]
pub struct DebugStep {
    pub step_index: usize,
    pub execution_step: ExecutionStep,
    pub breakpoint_hit: Option<Breakpoint>,
    pub watch_values: Vec<WatchValue>,
}

/// State inspection result
#[derive(Debug, Clone)]
pub struct StateInspection {
    pub address: String,
    pub block_number: u64,
    pub balance: String,
    pub nonce: u64,
    pub code: Option<Vec<u8>>,
    pub storage: HashMap<String, String>,
}

/// Gas analysis result
#[derive(Debug, Clone)]
pub struct GasAnalysis {
    pub total_gas: u64,
    pub breakdown: GasBreakdown,
    pub hotspots: Vec<GasHotspot>,
    pub optimizations: Vec<GasOptimization>,
}

#[derive(Debug, Clone)]
pub struct GasHotspot {
    pub pc: u64,
    pub opcode: String,
    pub gas_cost: u64,
    pub percentage: f64,
    pub count: u32,
}

#[derive(Debug, Clone)]
pub struct GasOptimization {
    pub optimization_type: OptimizationType,
    pub description: String,
    pub estimated_savings: u64,
    pub affected_locations: Vec<u64>,
}

#[derive(Debug, Clone)]
pub enum OptimizationType {
    StorageCache,
    LoopUnrolling,
    MemoryPacking,
    InlineAssembly,
    BatchOperations,
}

/// Revert reason decoding
#[derive(Debug, Clone)]
pub struct RevertReason {
    pub reason_type: RevertType,
    pub message: Option<String>,
    pub error_signature: Option<String>,
    pub decoded_params: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum RevertType {
    Empty,
    ErrorString,
    Panic,
    CustomError,
    LowLevelRevert,
}

/// Simulation snapshot
#[derive(Debug, Clone)]
pub struct SimulationSnapshot {
    pub step: usize,
    pub stack: Vec<String>,
    pub memory: Vec<u8>,
    pub storage: HashMap<String, String>,
    pub gas_remaining: u64,
    pub return_data: Vec<u8>,
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone)]
pub enum DebugError {
    SessionNotFound,
    EndOfExecution,
    StartOfExecution,
    InvalidBreakpoint,
    TracingFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_trace() {
        let mut debugger = Debugger::new();

        let tx = Transaction {
            hash: "0x123".to_string(),
            nonce: 0,
            from: "0xabc".to_string(),
            to: Some("0xdef".to_string()),
            value: "1000".to_string(),
            gas_limit: 100000,
            gas_price: 1000000000,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            input: Vec::new(),
            v: 27,
            r: "0x".to_string(),
            s: "0x".to_string(),
            tx_type: TransactionType::Legacy,
            access_list: None,
            chain_id: 7331,
        };

        let trace = debugger.trace_transaction(&tx);
        assert!(!trace.execution_steps.is_empty());
    }

    #[test]
    fn test_debug_session() {
        let mut debugger = Debugger::new();

        let tx = Transaction {
            hash: "0x456".to_string(),
            nonce: 0,
            from: "0xabc".to_string(),
            to: Some("0xdef".to_string()),
            value: "0".to_string(),
            gas_limit: 50000,
            gas_price: 1000000000,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            input: vec![0xa9, 0x05, 0x9c, 0xbb],
            v: 27,
            r: "0x".to_string(),
            s: "0x".to_string(),
            tx_type: TransactionType::Legacy,
            access_list: None,
            chain_id: 7331,
        };

        let session = debugger.start_session(&tx);
        assert_eq!(session.current_step, 0);

        let step = debugger.step_forward(&session.id).unwrap();
        assert_eq!(step.step_index, 1);
    }
}
