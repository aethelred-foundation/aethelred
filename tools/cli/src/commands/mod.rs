//! Command implementations for the Aethelred CLI
//!
//! This module contains all CLI command implementations for the Aethelred platform.
//! Each submodule handles a specific command group with enterprise-grade features.
//!
//! ## Command Categories
//!
//! - **Project Management**: `init`, `deploy`
//! - **Model Operations**: `model` (register, deploy, quantize, benchmark)
//! - **Compute Jobs**: `job` (submit, list, wait, logs)
//! - **Digital Seals**: `seal` (create, verify, export)
//! - **Validator Operations**: `validator` (register, stake, unstake)
//! - **Account Management**: `account` (create, import, send)
//! - **Network Operations**: `network` (status, switch, blocks)
//! - **Development Tools**: `dev` (serve, test, codegen)
//! - **Benchmarking**: `bench` (inference, training, network)
//! - **Configuration**: `config_cmd` (set, get, export)
//! - **Node Operations**: `node` (start, stop, status)
//! - **Compliance**: `compliance` (check, analyze, transfer, audit)
//! - **Hardware**: `hardware` (detect, simulate, attest, validate)

pub mod account;
pub mod api;
pub mod bench;
pub mod compliance;
pub mod config_cmd;
pub mod deploy;
pub mod dev;
pub mod hardware;
pub mod init;
pub mod job;
pub mod model;
pub mod network;
pub mod node;
pub mod query;
pub mod seal;
pub mod tx;
pub mod validator;
