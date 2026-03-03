//! # Transaction Building
//!
//! Build and sign Aethelred transactions.

use crate::crypto::{HybridKeypair, HybridSignature};
use serde::{Deserialize, Serialize};

/// Transaction builder
pub struct TxBuilder {
    messages: Vec<TxMessage>,
    memo: String,
    gas_limit: u64,
    fee: u64,
}

impl TxBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        TxBuilder {
            messages: vec![],
            memo: String::new(),
            gas_limit: 200_000,
            fee: 1000,
        }
    }

    /// Add a message
    pub fn add_message(mut self, msg: TxMessage) -> Self {
        self.messages.push(msg);
        self
    }

    /// Set memo
    pub fn memo(mut self, memo: &str) -> Self {
        self.memo = memo.to_string();
        self
    }

    /// Set gas limit
    pub fn gas_limit(mut self, limit: u64) -> Self {
        self.gas_limit = limit;
        self
    }

    /// Set fee
    pub fn fee(mut self, fee: u64) -> Self {
        self.fee = fee;
        self
    }

    /// Build unsigned transaction
    pub fn build(self) -> UnsignedTx {
        UnsignedTx {
            messages: self.messages,
            memo: self.memo,
            gas_limit: self.gas_limit,
            fee: self.fee,
        }
    }
}

impl Default for TxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Unsigned transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTx {
    /// Ordered transaction messages to execute.
    pub messages: Vec<TxMessage>,
    /// Optional free-form memo.
    pub memo: String,
    /// Maximum gas units the sender is willing to consume.
    pub gas_limit: u64,
    /// Transaction fee amount (chain native units).
    pub fee: u64,
}

impl UnsignedTx {
    /// Sign the transaction
    pub fn sign(self, keypair: &HybridKeypair) -> SignedTx {
        let bytes = self.to_sign_bytes();
        let signature = keypair.sign(&bytes);

        SignedTx {
            body: self,
            signature,
            signer: keypair.public_key(),
        }
    }

    /// Get bytes to sign
    pub fn to_sign_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }
}

/// Signed transaction
#[derive(Debug, Clone)]
pub struct SignedTx {
    /// Unsigned transaction body that was signed.
    pub body: UnsignedTx,
    /// Hybrid signature over `body.to_sign_bytes()`.
    pub signature: HybridSignature,
    /// Public key corresponding to the signer.
    pub signer: crate::crypto::HybridPublicKey,
}

impl SignedTx {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.body.to_sign_bytes();
        bytes.extend(self.signature.to_bytes());
        bytes.extend(self.signer.to_bytes());
        bytes
    }

    /// Verify signature
    pub fn verify(&self) -> bool {
        let msg = self.body.to_sign_bytes();
        self.signer.verify(&msg, &self.signature)
    }
}

/// Transaction message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxMessage {
    /// Create a Digital Seal
    CreateSeal {
        /// Hash of the model binary/manifest used for inference.
        model_hash: [u8; 32],
        /// Hash of the canonicalized inference input payload.
        input_hash: [u8; 32],
        /// Hash of the canonicalized inference output payload.
        output_hash: [u8; 32],
        /// Serialized TEE attestation/quote bytes bound to the execution.
        attestation: Vec<u8>,
    },

    /// Transfer tokens
    Transfer {
        /// Recipient account address.
        to: String,
        /// Amount to transfer.
        amount: u64,
        /// Denomination symbol (e.g. `uaethel`).
        denom: String,
    },

    /// Register a model
    RegisterModel {
        /// Human-readable model name.
        name: String,
        /// Model version string.
        version: String,
        /// Trusted enclave measurement for model execution.
        mrenclave: [u8; 32],
    },

    /// Submit compute job
    SubmitJob {
        /// Registry identifier of the model to invoke.
        model_id: String,
        /// Hash of the submitted job input payload.
        input_hash: [u8; 32],
        /// Maximum gas budget permitted for execution.
        max_gas: u64,
    },
}
