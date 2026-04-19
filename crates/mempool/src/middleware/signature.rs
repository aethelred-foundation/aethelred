//! Signature Verification Middleware
//!
//! Enterprise-grade hybrid signature verification for transactions.
//!
//! # Features
//!
//! - Hybrid ECDSA + Dilithium3 verification
//! - Quantum threat level awareness
//! - Batch verification for efficiency
//! - Public key to address derivation verification

use super::{Middleware, MiddlewareAction, MiddlewareContext, MiddlewareResult, ParsedTransaction};
use aethelred_core::{
    crypto::{
        hash::transaction_hash,
        hybrid::{HybridPublicKey, HybridSignature, VerifierConfig},
    },
    types::Address,
};

/// Signature verification middleware
pub struct SignatureMiddleware {
    /// Enable batch verification for multiple transactions
    batch_enabled: bool,
}

impl SignatureMiddleware {
    /// Create new signature middleware
    pub fn new() -> Self {
        Self {
            batch_enabled: true,
        }
    }

    /// Disable batch verification
    pub fn without_batch(mut self) -> Self {
        self.batch_enabled = false;
        self
    }

    /// Parse transaction from bytes
    fn parse_transaction(&self, tx_bytes: &[u8]) -> Option<ParsedTransaction> {
        // Minimum transaction size
        if tx_bytes.len() < 100 {
            return None;
        }

        // Parse header
        // Format: [tx_len:4][version:1][type:1][sender:21][nonce:8][gas_price:8][gas_limit:8][chain_id:8][expiry:8]...
        let mut offset = 0;

        // Skip tx_len if present (from signed transaction format)
        if tx_bytes.len() > 4 {
            let len =
                u32::from_le_bytes([tx_bytes[0], tx_bytes[1], tx_bytes[2], tx_bytes[3]]) as usize;

            if len > 0 && len < tx_bytes.len() {
                offset = 4;
            }
        }

        // Parse fields
        if offset + 63 > tx_bytes.len() {
            return None;
        }

        let _version = tx_bytes[offset];
        offset += 1;

        let tx_type = tx_bytes[offset];
        offset += 1;

        let mut sender = [0u8; 21];
        sender.copy_from_slice(&tx_bytes[offset..offset + 21]);
        offset += 21;

        let nonce = u64::from_le_bytes([
            tx_bytes[offset],
            tx_bytes[offset + 1],
            tx_bytes[offset + 2],
            tx_bytes[offset + 3],
            tx_bytes[offset + 4],
            tx_bytes[offset + 5],
            tx_bytes[offset + 6],
            tx_bytes[offset + 7],
        ]);
        offset += 8;

        let gas_price = u64::from_le_bytes([
            tx_bytes[offset],
            tx_bytes[offset + 1],
            tx_bytes[offset + 2],
            tx_bytes[offset + 3],
            tx_bytes[offset + 4],
            tx_bytes[offset + 5],
            tx_bytes[offset + 6],
            tx_bytes[offset + 7],
        ]);
        offset += 8;

        let gas_limit = u64::from_le_bytes([
            tx_bytes[offset],
            tx_bytes[offset + 1],
            tx_bytes[offset + 2],
            tx_bytes[offset + 3],
            tx_bytes[offset + 4],
            tx_bytes[offset + 5],
            tx_bytes[offset + 6],
            tx_bytes[offset + 7],
        ]);
        offset += 8;

        let chain_id = u64::from_le_bytes([
            tx_bytes[offset],
            tx_bytes[offset + 1],
            tx_bytes[offset + 2],
            tx_bytes[offset + 3],
            tx_bytes[offset + 4],
            tx_bytes[offset + 5],
            tx_bytes[offset + 6],
            tx_bytes[offset + 7],
        ]);

        // Compute transaction ID (hash of transaction bytes)
        let tx_id = self.compute_tx_hash(tx_bytes);

        Some(ParsedTransaction {
            tx_id,
            sender,
            tx_type,
            nonce,
            gas_price,
            gas_limit,
            chain_id,
            size: tx_bytes.len(),
            signature_valid: false, // Will be set by verification
            compliance_metadata: None,
        })
    }

    /// Compute transaction hash
    fn compute_tx_hash(&self, tx_bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"aethelred:transaction:v1:");
        hasher.update(tx_bytes);
        let result = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify hybrid signature
    fn verify_signature(&self, tx_bytes: &[u8], quantum_threat_level: u8) -> Result<bool, String> {
        // In signed transaction format:
        // [tx_len:4][tx_bytes:tx_len][sig_len:4][signature:sig_len][pk_len:4][public_key:pk_len]

        if tx_bytes.len() < 8 {
            return Err("Transaction too short".into());
        }

        let tx_len =
            u32::from_le_bytes([tx_bytes[0], tx_bytes[1], tx_bytes[2], tx_bytes[3]]) as usize;

        if tx_bytes.len() < 4 + tx_len + 4 {
            return Err("Invalid transaction format".into());
        }

        let sig_offset = 4 + tx_len;
        let sig_len = u32::from_le_bytes([
            tx_bytes[sig_offset],
            tx_bytes[sig_offset + 1],
            tx_bytes[sig_offset + 2],
            tx_bytes[sig_offset + 3],
        ]) as usize;

        if tx_bytes.len() < sig_offset + 4 + sig_len + 4 {
            return Err("Invalid signature section".into());
        }

        let pk_offset = sig_offset + 4 + sig_len;
        let pk_len = u32::from_le_bytes([
            tx_bytes[pk_offset],
            tx_bytes[pk_offset + 1],
            tx_bytes[pk_offset + 2],
            tx_bytes[pk_offset + 3],
        ]) as usize;

        if tx_bytes.len() < pk_offset + 4 + pk_len {
            return Err("Invalid public key section".into());
        }

        // Extract components
        let tx_data = &tx_bytes[4..4 + tx_len];
        let signature = &tx_bytes[sig_offset + 4..sig_offset + 4 + sig_len];
        let public_key = &tx_bytes[pk_offset + 4..pk_offset + 4 + pk_len];

        if tx_data.len() < 23 {
            return Err("Transaction body too short".into());
        }

        let signer = HybridPublicKey::from_bytes(public_key)
            .map_err(|e| format!("Invalid hybrid public key: {e}"))?;
        let signature = HybridSignature::from_bytes(signature)
            .map_err(|e| format!("Invalid hybrid signature: {e}"))?;

        let expected_sender = &tx_data[2..23];
        let derived_sender = Address::from_public_key(&signer).serialize();
        if derived_sender.as_slice() != expected_sender {
            return Ok(false);
        }

        let chain_id_offset = 47;
        if tx_data.len() < chain_id_offset + 8 {
            return Err("Transaction body missing chain id".into());
        }
        let chain_id = u64::from_le_bytes(
            tx_data[chain_id_offset..chain_id_offset + 8]
                .try_into()
                .map_err(|_| "Invalid chain id encoding".to_string())?,
        );

        let verifier_config = verifier_config(chain_id, quantum_threat_level);

        let tx_hash = transaction_hash(tx_data);
        signature
            .verify(tx_hash.as_bytes(), &signer, &verifier_config)
            .map(|_| true)
    }
}

fn verifier_config(chain_id: u64, quantum_threat_level: u8) -> VerifierConfig {
    let mut config = match chain_id {
        9999 => VerifierConfig::devnet(),
        2 => VerifierConfig::testnet(),
        1 => VerifierConfig::mainnet(),
        _ => {
            let mut config = VerifierConfig::default();
            config.chain_id = chain_id;
            config
        }
    };

    if quantum_threat_level >= 5 {
        config.enter_panic_mode();
    }

    config
}

impl Default for SignatureMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl Middleware for SignatureMiddleware {
    fn process(&self, ctx: &mut MiddlewareContext) -> MiddlewareResult<MiddlewareAction> {
        // 1. Check transaction size
        if ctx.tx_bytes.len() > ctx.config.max_tx_size {
            return Ok(MiddlewareAction::Reject(format!(
                "Transaction size {} exceeds maximum {}",
                ctx.tx_bytes.len(),
                ctx.config.max_tx_size
            )));
        }

        // 2. Parse transaction
        let mut parsed = match self.parse_transaction(&ctx.tx_bytes) {
            Some(p) => p,
            None => {
                return Ok(MiddlewareAction::Reject(
                    "Failed to parse transaction".into(),
                ))
            }
        };

        // 3. Check blocked addresses
        for blocked in &ctx.config.blocked_addresses {
            if &parsed.sender == blocked {
                return Ok(MiddlewareAction::Reject("Sender address is blocked".into()));
            }
        }

        // 4. Verify signature
        let signature_valid =
            match self.verify_signature(&ctx.tx_bytes, ctx.config.quantum_threat_level) {
                Ok(valid) => valid,
                Err(e) => {
                    return Ok(MiddlewareAction::Reject(format!(
                        "Signature verification error: {}",
                        e
                    )))
                }
            };

        if !signature_valid {
            return Ok(MiddlewareAction::Reject(
                "Signature verification failed".into(),
            ));
        }

        parsed.signature_valid = true;

        // 5. Store parsed transaction in context
        ctx.parsed_tx = Some(parsed);

        // 6. Add verification tags
        ctx.add_tag("signature_verified", "true");
        ctx.add_tag("signature_type", "hybrid");
        ctx.add_tag(
            "quantum_threat_level",
            ctx.config.quantum_threat_level.to_string(),
        );

        Ok(MiddlewareAction::Continue)
    }

    fn name(&self) -> &'static str {
        "signature"
    }

    fn priority(&self) -> u32 {
        10 // First in chain
    }
}

/// Batch signature verifier for multiple transactions
pub struct BatchSignatureVerifier {
    /// Accumulated transactions
    transactions: Vec<Vec<u8>>,
    /// Maximum batch size
    max_batch_size: usize,
}

impl BatchSignatureVerifier {
    /// Create new batch verifier
    pub fn new(max_batch_size: usize) -> Self {
        Self {
            transactions: Vec::new(),
            max_batch_size,
        }
    }

    /// Add transaction to batch
    pub fn add(&mut self, tx_bytes: Vec<u8>) -> bool {
        if self.transactions.len() >= self.max_batch_size {
            return false;
        }
        self.transactions.push(tx_bytes);
        true
    }

    /// Verify all transactions in batch
    pub fn verify_all(&self, quantum_threat_level: u8) -> Vec<bool> {
        // In production, this would use batch verification
        // which is more efficient for Dilithium

        let middleware = SignatureMiddleware::new();
        self.transactions
            .iter()
            .map(|tx| {
                middleware
                    .verify_signature(tx, quantum_threat_level)
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Clear batch
    pub fn clear(&mut self) {
        self.transactions.clear();
    }

    /// Get batch size
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aethelred_core::{
        crypto::hybrid::HybridKeyPair,
        types::{Address, AddressType, Transaction},
    };
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };

    static NEXT_TEST_NONCE: AtomicU64 = AtomicU64::new(1);

    fn create_test_context(tx_bytes: Vec<u8>) -> MiddlewareContext {
        let config = Arc::new(super::super::MiddlewareConfig::default());
        MiddlewareContext::new(tx_bytes, config)
    }

    fn create_signed_transaction() -> Vec<u8> {
        let keypair = HybridKeyPair::generate().unwrap();
        let sender = Address::from_public_key(keypair.public_key());
        let recipient = Address::from_bytes([0x42; 20], AddressType::User);
        let nonce = NEXT_TEST_NONCE.fetch_add(1, Ordering::Relaxed);

        Transaction::transfer(sender, recipient, 1_000, nonce)
            .with_chain_id(1)
            .sign(&keypair)
            .unwrap()
            .to_bytes()
    }

    #[test]
    fn test_signature_middleware() {
        let middleware = SignatureMiddleware::new();
        let tx = create_signed_transaction();
        let mut ctx = create_test_context(tx);

        let action = middleware.process(&mut ctx).unwrap();

        // Should continue with valid signature
        assert_eq!(action, MiddlewareAction::Continue);
        assert!(ctx.parsed_tx.is_some());
        assert!(ctx.parsed_tx.as_ref().unwrap().signature_valid);
    }

    #[test]
    fn test_reject_oversized() {
        let middleware = SignatureMiddleware::new();
        let large_tx = vec![0u8; 2_000_000]; // 2 MB
        let mut ctx = create_test_context(large_tx);

        let action = middleware.process(&mut ctx).unwrap();

        match action {
            MiddlewareAction::Reject(reason) => {
                assert!(reason.contains("exceeds maximum"));
            }
            _ => panic!("Expected rejection"),
        }
    }

    #[test]
    fn test_reject_invalid_format() {
        let middleware = SignatureMiddleware::new();
        let short_tx = vec![0u8; 10];
        let mut ctx = create_test_context(short_tx);

        let action = middleware.process(&mut ctx).unwrap();

        assert!(matches!(action, MiddlewareAction::Reject(_)));
    }

    #[test]
    fn test_batch_verifier() {
        let mut batch = BatchSignatureVerifier::new(100);
        let tx = create_signed_transaction();

        assert!(batch.add(tx.clone()));
        assert!(batch.add(tx.clone()));
        assert_eq!(batch.len(), 2);

        let results = batch.verify_all(0);
        assert_eq!(results.len(), 2);
        assert!(results.into_iter().all(|valid| valid));

        batch.clear();
        assert!(batch.is_empty());
    }

    #[test]
    fn test_reject_tampered_signature() {
        let middleware = SignatureMiddleware::new();
        let mut tx = create_signed_transaction();
        let sig_offset = 4 + u32::from_le_bytes(tx[0..4].try_into().unwrap()) as usize;
        let sig_len =
            u32::from_le_bytes(tx[sig_offset..sig_offset + 4].try_into().unwrap()) as usize;
        let sig_start = sig_offset + 4;
        tx[sig_start + sig_len - 1] ^= 0x01;

        let mut ctx = create_test_context(tx);
        let action = middleware.process(&mut ctx).unwrap();

        assert!(matches!(action, MiddlewareAction::Reject(_)));
    }
}
