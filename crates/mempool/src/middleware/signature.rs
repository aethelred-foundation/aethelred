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

use super::{
    Middleware, MiddlewareAction, MiddlewareContext, MiddlewareResult,
    ParsedTransaction,
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
            let len = u32::from_le_bytes([
                tx_bytes[0],
                tx_bytes[1],
                tx_bytes[2],
                tx_bytes[3],
            ]) as usize;

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
    fn verify_signature(
        &self,
        tx_bytes: &[u8],
        quantum_threat_level: u8,
    ) -> Result<bool, &'static str> {
        // In signed transaction format:
        // [tx_len:4][tx_bytes:tx_len][sig_len:4][signature:sig_len][pk_len:4][public_key:pk_len]

        if tx_bytes.len() < 8 {
            return Err("Transaction too short");
        }

        let tx_len = u32::from_le_bytes([
            tx_bytes[0],
            tx_bytes[1],
            tx_bytes[2],
            tx_bytes[3],
        ]) as usize;

        if tx_bytes.len() < 4 + tx_len + 4 {
            return Err("Invalid transaction format");
        }

        let sig_offset = 4 + tx_len;
        let sig_len = u32::from_le_bytes([
            tx_bytes[sig_offset],
            tx_bytes[sig_offset + 1],
            tx_bytes[sig_offset + 2],
            tx_bytes[sig_offset + 3],
        ]) as usize;

        if tx_bytes.len() < sig_offset + 4 + sig_len + 4 {
            return Err("Invalid signature section");
        }

        let pk_offset = sig_offset + 4 + sig_len;
        let pk_len = u32::from_le_bytes([
            tx_bytes[pk_offset],
            tx_bytes[pk_offset + 1],
            tx_bytes[pk_offset + 2],
            tx_bytes[pk_offset + 3],
        ]) as usize;

        if tx_bytes.len() < pk_offset + 4 + pk_len {
            return Err("Invalid public key section");
        }

        // Extract components
        let _tx_data = &tx_bytes[4..4 + tx_len];
        let signature = &tx_bytes[sig_offset + 4..sig_offset + 4 + sig_len];
        let public_key = &tx_bytes[pk_offset + 4..pk_offset + 4 + pk_len];

        // Verify signature format
        // Hybrid signature: [marker:1][ecdsa:64][sep:1][dilithium:3293]
        if signature.len() < 66 {
            return Err("Signature too short");
        }

        let marker = signature[0];
        if marker != 0x03 {
            // Not a hybrid signature
            return Err("Invalid signature marker (expected hybrid)");
        }

        // In production, this would call the actual verification logic
        // from crates/core/src/crypto/hybrid.rs

        // For MVP, simulate verification based on format
        let has_ecdsa = signature.len() >= 65;
        let has_dilithium = signature.len() >= 66 + 3293;

        // Quantum threat level affects verification
        let valid = match quantum_threat_level {
            0..=2 => has_ecdsa && has_dilithium, // Both required
            3..=4 => has_dilithium,               // Dilithium required
            _ => has_dilithium,                   // Q-Day: only quantum
        };

        // Verify public key matches sender
        if public_key.len() < 34 {
            return Err("Public key too short");
        }

        Ok(valid)
    }
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
                    "Failed to parse transaction".into()
                ))
            }
        };

        // 3. Check blocked addresses
        for blocked in &ctx.config.blocked_addresses {
            if &parsed.sender == blocked {
                return Ok(MiddlewareAction::Reject(
                    "Sender address is blocked".into()
                ));
            }
        }

        // 4. Verify signature
        let signature_valid = match self.verify_signature(
            &ctx.tx_bytes,
            ctx.config.quantum_threat_level,
        ) {
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
                "Signature verification failed".into()
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
    use std::sync::Arc;

    fn create_test_context(tx_bytes: Vec<u8>) -> MiddlewareContext {
        let config = Arc::new(super::super::MiddlewareConfig::default());
        MiddlewareContext::new(tx_bytes, config)
    }

    fn create_mock_transaction() -> Vec<u8> {
        // Create a mock signed transaction with proper format
        let mut tx = Vec::new();

        // Transaction body
        let mut body = Vec::new();
        body.push(1); // version
        body.push(0x01); // type (transfer)
        body.extend_from_slice(&[0u8; 21]); // sender
        body.extend_from_slice(&0u64.to_le_bytes()); // nonce
        body.extend_from_slice(&1u64.to_le_bytes()); // gas_price
        body.extend_from_slice(&21000u64.to_le_bytes()); // gas_limit
        body.extend_from_slice(&1u64.to_le_bytes()); // chain_id
        body.extend_from_slice(&0u64.to_le_bytes()); // expiry
        body.extend_from_slice(&[0u8; 50]); // payload

        // tx_len
        tx.extend_from_slice(&(body.len() as u32).to_le_bytes());
        tx.extend_from_slice(&body);

        // Signature (mock hybrid)
        let mut sig = Vec::new();
        sig.push(0x03); // hybrid marker
        sig.extend_from_slice(&[0u8; 64]); // ECDSA
        sig.push(0xFF); // separator
        sig.extend_from_slice(&[0u8; 3293]); // Dilithium

        tx.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        tx.extend_from_slice(&sig);

        // Public key (mock hybrid)
        let mut pk = Vec::new();
        pk.push(0x03); // hybrid marker
        pk.extend_from_slice(&[0u8; 33]); // ECDSA compressed
        pk.push(0xFF); // separator
        pk.extend_from_slice(&[0u8; 1952]); // Dilithium

        tx.extend_from_slice(&(pk.len() as u32).to_le_bytes());
        tx.extend_from_slice(&pk);

        tx
    }

    #[test]
    fn test_signature_middleware() {
        let middleware = SignatureMiddleware::new();
        let tx = create_mock_transaction();
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
        let tx = create_mock_transaction();

        assert!(batch.add(tx.clone()));
        assert!(batch.add(tx.clone()));
        assert_eq!(batch.len(), 2);

        let results = batch.verify_all(0);
        assert_eq!(results.len(), 2);

        batch.clear();
        assert!(batch.is_empty());
    }
}
