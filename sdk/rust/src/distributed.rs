//! Distributed training support (feature-gated placeholder module).
//!
//! This file exists to keep the crate module tree complete for tooling such as
//! `cargo fmt` and docs builds. The production distributed training
//! implementation is planned under the `distributed` feature.

#![allow(missing_docs)]

use crate::core::error::{AethelredError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    MPI,
    NCCL,
    Gloo,
    Mock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeROStage {
    Stage1,
    Stage2,
    Stage3,
}

#[derive(Debug, Default, Clone)]
pub struct ProcessGroup {
    world_size: usize,
    rank: usize,
}

impl ProcessGroup {
    pub fn new(world_size: usize, rank: usize) -> Self {
        Self { world_size, rank }
    }

    pub fn world_size(&self) -> usize {
        self.world_size
    }

    pub fn rank(&self) -> usize {
        self.rank
    }
}

#[derive(Debug, Default, Clone)]
pub struct DistributedDataParallel;

#[derive(Debug, Default, Clone)]
pub struct ZeROOptimizer;

#[derive(Debug, Default, Clone)]
pub struct PipelineParallel;

#[derive(Debug, Default, Clone)]
pub struct ColumnParallelLinear;

#[derive(Debug, Default, Clone)]
pub struct RowParallelLinear;

pub fn not_available() -> Result<()> {
    Err(AethelredError::Unknown(
        "distributed feature is enabled but the distributed module is a placeholder in this SDK build"
            .to_string(),
    ))
}
