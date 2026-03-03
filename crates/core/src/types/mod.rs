//! Aethelred Core Types
//!
//! Core data structures for the Aethelred blockchain:
//! - Transactions with hybrid post-quantum signatures
//! - Blocks and block headers
//! - Digital Seals for verified AI computations
//! - Compute jobs and verification results

pub mod address;
pub mod block;
pub mod job;
pub mod seal;
pub mod transaction;

pub use address::{Address, AddressType};
pub use block::{Block, BlockHeader, BlockId};
pub use job::{ComputeJob, ComputeResult, JobId, JobStatus};
pub use seal::{DigitalSeal, SealEvidence, SealId, SealStatus};
pub use transaction::{
    ComputeJobTx, SealTx, SignedTransaction, Transaction, TransactionId, TransactionType,
    TransferTx,
};
