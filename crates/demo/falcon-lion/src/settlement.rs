//! # Cross-Border Settlement Engine
//!
//! Enterprise-grade blockchain settlement for Zero-Knowledge Letters of Credit.
//! Enables trustless cross-border trade finance by verifying cryptographic proofs
//! from multiple jurisdictions without exposing underlying data.
//!
//! ## Settlement Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────────────────┐
//! │                    ZERO-KNOWLEDGE LETTER OF CREDIT SETTLEMENT                            │
//! ├─────────────────────────────────────────────────────────────────────────────────────────┤
//! │                                                                                          │
//! │  STEP 1: PROOF SUBMISSION                                                               │
//! │  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
//! │  │                                                                                    │  │
//! │  │   UAE (FAB) Node                              Singapore (DBS) Node                │  │
//! │  │   ┌─────────────────┐                        ┌─────────────────┐                  │  │
//! │  │   │ Sanctions Proof │                        │ Credit Score    │                  │  │
//! │  │   │ ✅ PASSED       │────────────┬───────────│ Proof ✅ 98/100 │                  │  │
//! │  │   │                 │            │           │                 │                  │  │
//! │  │   │ Data: 🔒        │            │           │ Data: 🔒        │                  │  │
//! │  │   │ (Never leaves   │            │           │ (Never leaves   │                  │  │
//! │  │   │  UAE)           │            │           │  Singapore)     │                  │  │
//! │  │   └─────────────────┘            │           └─────────────────┘                  │  │
//! │  │                                  │                                                │  │
//! │  └──────────────────────────────────┼────────────────────────────────────────────────┘  │
//! │                                     │                                                    │
//! │                                     ▼                                                    │
//! │  STEP 2: SMART CONTRACT VERIFICATION                                                    │
//! │  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
//! │  │                                                                                    │  │
//! │  │   ┌─────────────────────────────────────────────────────────────────────────────┐│  │
//! │  │   │                     TradeSettlement Smart Contract                          ││  │
//! │  │   │                                                                             ││  │
//! │  │   │   function mintLetterOfCredit(                                              ││  │
//! │  │   │       bytes calldata exporterProof,                                         ││  │
//! │  │   │       bytes calldata importerProof,                                         ││  │
//! │  │   │       uint256 amount,                                                       ││  │
//! │  │   │       address beneficiary                                                   ││  │
//! │  │   │   ) external returns (bytes32 lcId)                                         ││  │
//! │  │   │                                                                             ││  │
//! │  │   │   1. Verify Dilithium signatures on both proofs                            ││  │
//! │  │   │   2. Check proof expiry timestamps                                          ││  │
//! │  │   │   3. Validate jurisdictional compliance flags                               ││  │
//! │  │   │   4. Mint vLC (Verifiable Letter of Credit) NFT                            ││  │
//! │  │   │   5. Emit LetterOfCreditMinted event                                        ││  │
//! │  │   │                                                                             ││  │
//! │  │   └─────────────────────────────────────────────────────────────────────────────┘│  │
//! │  │                                                                                    │  │
//! │  └───────────────────────────────────────────────────────────────────────────────────┘  │
//! │                                     │                                                    │
//! │                                     ▼                                                    │
//! │  STEP 3: LC MINTED ON-CHAIN                                                             │
//! │  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
//! │  │                                                                                    │  │
//! │  │   🎉 VERIFIABLE LETTER OF CREDIT MINTED                                          │  │
//! │  │                                                                                    │  │
//! │  │   LC Reference: VLC-2024-FAB-DBS-001                                              │  │
//! │  │   Amount: $5,000,000 USD                                                          │  │
//! │  │   Beneficiary: UAE Solar Manufacturing Co.                                        │  │
//! │  │   Applicant: Singapore Construction Pte Ltd                                       │  │
//! │  │   Expiry: 2024-12-31                                                              │  │
//! │  │   Settlement TX: 0x1234...5678                                                    │  │
//! │  │   Cryptographic Signature: Dilithium3 (Post-Quantum)                              │  │
//! │  │                                                                                    │  │
//! │  └───────────────────────────────────────────────────────────────────────────────────┘  │
//! │                                                                                          │
//! └─────────────────────────────────────────────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
#[cfg(test)]
use uuid::Uuid;

use crate::error::{FalconLionError, FalconLionResult};
use crate::types::{
    BankIdentifier, Currency, Hash, MonetaryAmount, TradeDeal, TradeParticipant, VerificationProof,
};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Settlement contract version
pub const CONTRACT_VERSION: &str = "1.0.0";

/// Network identifier
pub const NETWORK_ID: &str = "aethelred-mainnet";

/// Minimum confirmations for finality
pub const MIN_CONFIRMATIONS: u32 = 6;

/// Gas price floor (in gwei equivalent)
pub const GAS_PRICE_FLOOR: u64 = 20;

/// Maximum gas per transaction
pub const MAX_GAS: u64 = 1_000_000;

// =============================================================================
// SMART CONTRACT TYPES
// =============================================================================

/// Smart contract address (20 bytes)
pub type ContractAddress = [u8; 20];

/// Transaction hash (32 bytes)
pub type TxHash = [u8; 32];

/// Block number
pub type BlockNumber = u64;

/// Verifiable Letter of Credit (on-chain representation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableLetterOfCredit {
    /// On-chain LC ID (hash)
    pub lc_id: Hash,
    /// Off-chain LC reference
    pub reference: String,
    /// Amount in smallest unit
    pub amount: u128,
    /// Currency code
    pub currency: Currency,
    /// Beneficiary address (on-chain)
    pub beneficiary_address: ContractAddress,
    /// Applicant address (on-chain)
    pub applicant_address: ContractAddress,
    /// Issuing bank node ID
    pub issuing_bank_node: String,
    /// Advising bank node ID
    pub advising_bank_node: String,
    /// Exporter proof hash
    pub exporter_proof_hash: Hash,
    /// Importer proof hash
    pub importer_proof_hash: Hash,
    /// Issue timestamp
    pub issued_at: u64,
    /// Expiry timestamp
    pub expires_at: u64,
    /// On-chain status
    pub status: OnChainLcStatus,
    /// Minting transaction hash
    pub mint_tx_hash: TxHash,
    /// Block number of minting
    pub mint_block: BlockNumber,
}

/// On-chain LC status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OnChainLcStatus {
    /// Minted and active
    Active,
    /// Documents submitted
    DocumentsSubmitted,
    /// Payment released
    PaymentReleased,
    /// Expired without draw
    Expired,
    /// Cancelled by issuing bank
    Cancelled,
    /// Disputed
    Disputed,
}

/// Settlement transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementTransaction {
    /// Transaction hash
    pub tx_hash: TxHash,
    /// From address
    pub from: ContractAddress,
    /// To address (contract)
    pub to: ContractAddress,
    /// Transaction type
    pub tx_type: SettlementTxType,
    /// Data payload
    pub data: Vec<u8>,
    /// Value transferred (in native token)
    pub value: u128,
    /// Gas used
    pub gas_used: u64,
    /// Gas price
    pub gas_price: u64,
    /// Block number
    pub block_number: BlockNumber,
    /// Block timestamp
    pub block_timestamp: u64,
    /// Confirmations
    pub confirmations: u32,
    /// Transaction status
    pub status: TxStatus,
}

/// Settlement transaction type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementTxType {
    /// Mint new LC
    MintLC,
    /// Submit documents
    SubmitDocuments,
    /// Release payment
    ReleasePayment,
    /// Cancel LC
    CancelLC,
    /// Amend LC
    AmendLC,
    /// Extend expiry
    ExtendExpiry,
    /// Dispute
    RaiseDispute,
    /// Resolve dispute
    ResolveDispute,
}

/// Transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxStatus {
    Pending,
    Confirmed,
    Finalized,
    Failed,
    Reverted,
}

// =============================================================================
// SETTLEMENT ENGINE
// =============================================================================

/// Cross-border settlement engine
pub struct SettlementEngine {
    /// Contract address
    contract_address: ContractAddress,
    /// Network configuration
    network: NetworkConfig,
    /// Active LCs
    active_lcs: Arc<RwLock<HashMap<Hash, VerifiableLetterOfCredit>>>,
    /// Transaction history
    tx_history: Arc<RwLock<Vec<SettlementTransaction>>>,
    /// Block height
    current_block: Arc<RwLock<BlockNumber>>,
    /// Settlement metrics
    metrics: Arc<RwLock<SettlementMetrics>>,
    /// Event subscribers
    event_callbacks: Arc<RwLock<Vec<Box<dyn Fn(&SettlementEvent) + Send + Sync>>>>,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network ID
    pub network_id: String,
    /// Chain ID
    pub chain_id: u64,
    /// RPC endpoint
    pub rpc_endpoint: String,
    /// Block time (seconds)
    pub block_time_secs: u64,
    /// Confirmations for finality
    pub finality_confirmations: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            network_id: NETWORK_ID.to_string(),
            chain_id: 1337, // Aethelred chain ID
            rpc_endpoint: "https://rpc.aethelred.org".to_string(),
            block_time_secs: 6,
            finality_confirmations: MIN_CONFIRMATIONS,
        }
    }
}

/// Settlement metrics
#[derive(Debug, Default)]
pub struct SettlementMetrics {
    /// Total LCs minted
    pub total_lcs_minted: u64,
    /// Total value settled (USD equivalent)
    pub total_value_settled_usd: u128,
    /// Average settlement time (seconds)
    pub avg_settlement_time_secs: u64,
    /// Total gas used
    pub total_gas_used: u64,
    /// Failed transactions
    pub failed_transactions: u64,
    /// Disputes raised
    pub disputes_raised: u64,
    /// Disputes resolved
    pub disputes_resolved: u64,
}

/// Settlement event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementEvent {
    /// Event type
    pub event_type: SettlementEventType,
    /// LC ID
    pub lc_id: Option<Hash>,
    /// Transaction hash
    pub tx_hash: Option<TxHash>,
    /// Block number
    pub block_number: BlockNumber,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Event data
    pub data: HashMap<String, String>,
}

/// Settlement event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementEventType {
    LcMinted,
    DocumentsSubmitted,
    PaymentReleased,
    LcExpired,
    LcCancelled,
    DisputeRaised,
    DisputeResolved,
    ProofVerified,
    TransactionConfirmed,
    TransactionFinalized,
}

impl SettlementEngine {
    /// Create new settlement engine
    pub fn new() -> Self {
        let contract_address = Self::derive_contract_address();

        Self {
            contract_address,
            network: NetworkConfig::default(),
            active_lcs: Arc::new(RwLock::new(HashMap::new())),
            tx_history: Arc::new(RwLock::new(Vec::new())),
            current_block: Arc::new(RwLock::new(1)),
            metrics: Arc::new(RwLock::new(SettlementMetrics::default())),
            event_callbacks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create with custom network config
    pub fn with_network(network: NetworkConfig) -> Self {
        let mut engine = Self::new();
        engine.network = network;
        engine
    }

    /// Derive contract address (deterministic)
    fn derive_contract_address() -> ContractAddress {
        let mut hasher = Keccak256::new();
        hasher.update(b"TradeSettlement");
        hasher.update(CONTRACT_VERSION.as_bytes());
        hasher.update(&[0x01]); // Deployment nonce
        let hash = hasher.finalize();
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..32]);
        address
    }

    /// Get contract address
    pub fn contract_address(&self) -> ContractAddress {
        self.contract_address
    }

    /// Get contract address as hex string
    pub fn contract_address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.contract_address))
    }

    /// Mint a Verifiable Letter of Credit
    ///
    /// This is the core settlement function that:
    /// 1. Verifies exporter proof (from UAE/FAB)
    /// 2. Verifies importer proof (from Singapore/DBS)
    /// 3. Mints the on-chain LC representation
    /// 4. Emits events for tracking
    pub async fn mint_letter_of_credit(
        &self,
        exporter_proof: &VerificationProof,
        importer_proof: &VerificationProof,
        deal: &TradeDeal,
        issuing_bank: &BankIdentifier,
        advising_bank: &BankIdentifier,
    ) -> FalconLionResult<VerifiableLetterOfCredit> {
        let start_time = std::time::Instant::now();

        tracing::info!(
            deal_id = %deal.id,
            exporter = %deal.exporter.legal_name,
            importer = %deal.importer.legal_name,
            amount = %deal.total_value,
            "Starting LC minting process"
        );

        // Step 1: Verify proofs
        self.verify_proof(exporter_proof)?;
        self.verify_proof(importer_proof)?;

        tracing::info!("Both proofs verified successfully");

        // Step 2: Validate proof jurisdictions
        if exporter_proof.data_jurisdiction != advising_bank.jurisdiction {
            return Err(FalconLionError::InvalidProof(format!(
                "Exporter proof jurisdiction {} does not match advising bank {}",
                exporter_proof.data_jurisdiction, advising_bank.jurisdiction
            )));
        }

        if importer_proof.data_jurisdiction != issuing_bank.jurisdiction {
            return Err(FalconLionError::InvalidProof(format!(
                "Importer proof jurisdiction {} does not match issuing bank {}",
                importer_proof.data_jurisdiction, issuing_bank.jurisdiction
            )));
        }

        // Step 3: Generate LC ID
        let lc_id = self.generate_lc_id(deal, exporter_proof, importer_proof);

        // Check if LC already exists
        if self.active_lcs.read().contains_key(&lc_id) {
            return Err(FalconLionError::LcAlreadyExists(hex::encode(lc_id)));
        }

        // Step 4: Convert amount to on-chain representation
        let amount_smallest_unit = self.to_smallest_unit(&deal.total_value);

        // Step 5: Generate addresses for participants
        let beneficiary_address = self.derive_participant_address(&deal.exporter);
        let applicant_address = self.derive_participant_address(&deal.importer);

        // Step 6: Calculate expiry
        let now = Utc::now();
        let expiry = now + Duration::days(90); // 90-day LC

        // Step 7: Simulate blockchain transaction
        let (tx_hash, block_number) = self
            .execute_mint_transaction(
                &lc_id,
                amount_smallest_unit,
                &beneficiary_address,
                &applicant_address,
                exporter_proof,
                importer_proof,
            )
            .await?;

        // Step 8: Create on-chain LC representation
        let vlc = VerifiableLetterOfCredit {
            lc_id,
            reference: format!(
                "VLC-{}-{}-{}-{:03}",
                now.format("%Y"),
                advising_bank.swift_code.chars().take(3).collect::<String>(),
                issuing_bank.swift_code.chars().take(3).collect::<String>(),
                self.metrics.read().total_lcs_minted + 1
            ),
            amount: amount_smallest_unit,
            currency: deal.total_value.currency,
            beneficiary_address,
            applicant_address,
            issuing_bank_node: issuing_bank.node_id.clone(),
            advising_bank_node: advising_bank.node_id.clone(),
            exporter_proof_hash: exporter_proof.proof_hash,
            importer_proof_hash: importer_proof.proof_hash,
            issued_at: now.timestamp() as u64,
            expires_at: expiry.timestamp() as u64,
            status: OnChainLcStatus::Active,
            mint_tx_hash: tx_hash,
            mint_block: block_number,
        };

        // Step 9: Store LC
        self.active_lcs.write().insert(lc_id, vlc.clone());

        // Step 10: Update metrics
        {
            let mut metrics = self.metrics.write();
            metrics.total_lcs_minted += 1;
            metrics.total_value_settled_usd +=
                self.to_usd_equivalent(amount_smallest_unit, deal.total_value.currency);

            let elapsed = start_time.elapsed().as_secs();
            let total_settlements = metrics.total_lcs_minted;
            metrics.avg_settlement_time_secs =
                (metrics.avg_settlement_time_secs * (total_settlements - 1) + elapsed)
                    / total_settlements;
        }

        // Step 11: Emit event
        self.emit_event(SettlementEvent {
            event_type: SettlementEventType::LcMinted,
            lc_id: Some(lc_id),
            tx_hash: Some(tx_hash),
            block_number,
            timestamp: now,
            data: {
                let mut data = HashMap::new();
                data.insert("reference".to_string(), vlc.reference.clone());
                data.insert("amount".to_string(), deal.total_value.formatted());
                data.insert("beneficiary".to_string(), deal.exporter.legal_name.clone());
                data.insert("applicant".to_string(), deal.importer.legal_name.clone());
                data
            },
        });

        tracing::info!(
            lc_id = %hex::encode(lc_id),
            reference = %vlc.reference,
            tx_hash = %hex::encode(tx_hash),
            block = block_number,
            "Letter of Credit minted successfully"
        );

        Ok(vlc)
    }

    /// Verify a proof
    fn verify_proof(&self, proof: &VerificationProof) -> FalconLionResult<()> {
        // Check expiry
        if Utc::now() > proof.expires_at {
            return Err(FalconLionError::ProofExpired);
        }

        // Verify proof hash matches bytes
        let computed_hash = self.hash_proof_bytes(&proof.proof_bytes);
        if computed_hash != proof.proof_hash {
            return Err(FalconLionError::InvalidProof("Hash mismatch".to_string()));
        }

        // Check result
        if !proof.result_summary.passed {
            return Err(FalconLionError::ProofVerificationFailed(
                "Proof did not pass verification".to_string(),
            ));
        }

        // Check confidence
        if proof.result_summary.confidence_score < 85 {
            return Err(FalconLionError::ProofVerificationFailed(format!(
                "Confidence score {} below threshold 85",
                proof.result_summary.confidence_score
            )));
        }

        Ok(())
    }

    /// Generate LC ID from deal and proofs
    fn generate_lc_id(
        &self,
        deal: &TradeDeal,
        exporter_proof: &VerificationProof,
        importer_proof: &VerificationProof,
    ) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(deal.id.as_bytes());
        hasher.update(&exporter_proof.proof_hash);
        hasher.update(&importer_proof.proof_hash);
        hasher.update(&Utc::now().timestamp().to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Hash proof bytes
    fn hash_proof_bytes(&self, bytes: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Convert monetary amount to smallest unit
    fn to_smallest_unit(&self, amount: &MonetaryAmount) -> u128 {
        let decimals = amount.currency.decimal_places();
        let multiplier = 10u128.pow(decimals as u32);
        (amount.amount * Decimal::from(multiplier))
            .to_string()
            .parse()
            .unwrap_or(0)
    }

    /// Convert to USD equivalent (simplified)
    fn to_usd_equivalent(&self, amount: u128, currency: Currency) -> u128 {
        let rate = match currency {
            Currency::Usd => 1_000_000, // 1:1
            Currency::Aed => 272_000,   // ~0.272 USD
            Currency::Sgd => 740_000,   // ~0.74 USD
            Currency::Eur => 1_080_000, // ~1.08 USD
            Currency::Gbp => 1_260_000, // ~1.26 USD
            _ => 1_000_000,
        };
        (amount * rate) / 1_000_000
    }

    /// Derive participant address from identity
    fn derive_participant_address(&self, participant: &TradeParticipant) -> ContractAddress {
        let mut hasher = Keccak256::new();
        hasher.update(participant.id.as_bytes());
        hasher.update(participant.registration_number.as_bytes());
        if let Some(lei) = &participant.lei {
            hasher.update(lei.as_bytes());
        }
        let hash = hasher.finalize();
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..32]);
        address
    }

    /// Execute mint transaction (simulated blockchain interaction)
    async fn execute_mint_transaction(
        &self,
        lc_id: &Hash,
        amount: u128,
        beneficiary: &ContractAddress,
        applicant: &ContractAddress,
        exporter_proof: &VerificationProof,
        importer_proof: &VerificationProof,
    ) -> FalconLionResult<(TxHash, BlockNumber)> {
        // Simulate transaction preparation
        let calldata = self.encode_mint_calldata(
            lc_id,
            amount,
            beneficiary,
            applicant,
            &exporter_proof.proof_bytes,
            &importer_proof.proof_bytes,
        );

        // Simulate block time delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Generate transaction hash
        let tx_hash = self.generate_tx_hash(&calldata);

        // Increment block
        let block_number = {
            let mut block = self.current_block.write();
            *block += 1;
            *block
        };

        // Record transaction
        let tx = SettlementTransaction {
            tx_hash,
            from: [0u8; 20], // Sender address (would be bank's address)
            to: self.contract_address,
            tx_type: SettlementTxType::MintLC,
            data: calldata.clone(),
            value: 0,
            gas_used: 250_000,
            gas_price: GAS_PRICE_FLOOR,
            block_number,
            block_timestamp: Utc::now().timestamp() as u64,
            confirmations: 1,
            status: TxStatus::Confirmed,
        };

        self.tx_history.write().push(tx);
        self.metrics.write().total_gas_used += 250_000;

        // Simulate confirmations (in real impl, this would be async)
        self.simulate_confirmations(tx_hash, block_number).await;

        Ok((tx_hash, block_number))
    }

    /// Encode mint function calldata
    fn encode_mint_calldata(
        &self,
        lc_id: &Hash,
        amount: u128,
        beneficiary: &ContractAddress,
        applicant: &ContractAddress,
        exporter_proof: &[u8],
        importer_proof: &[u8],
    ) -> Vec<u8> {
        let mut calldata = Vec::new();

        // Function selector: mintLetterOfCredit(bytes32,uint256,address,address,bytes,bytes)
        let selector = self.compute_function_selector(
            "mintLetterOfCredit(bytes32,uint256,address,address,bytes,bytes)",
        );
        calldata.extend_from_slice(&selector);

        // LC ID (bytes32)
        calldata.extend_from_slice(lc_id);

        // Amount (uint256, padded to 32 bytes)
        let mut amount_bytes = [0u8; 32];
        amount_bytes[16..].copy_from_slice(&amount.to_be_bytes());
        calldata.extend_from_slice(&amount_bytes);

        // Beneficiary address (padded to 32 bytes)
        let mut beneficiary_padded = [0u8; 32];
        beneficiary_padded[12..].copy_from_slice(beneficiary);
        calldata.extend_from_slice(&beneficiary_padded);

        // Applicant address (padded to 32 bytes)
        let mut applicant_padded = [0u8; 32];
        applicant_padded[12..].copy_from_slice(applicant);
        calldata.extend_from_slice(&applicant_padded);

        // Proof data offsets and lengths would follow...
        // (Simplified for demo purposes)
        calldata.extend_from_slice(&(exporter_proof.len() as u32).to_be_bytes());
        calldata.extend_from_slice(exporter_proof);
        calldata.extend_from_slice(&(importer_proof.len() as u32).to_be_bytes());
        calldata.extend_from_slice(importer_proof);

        calldata
    }

    /// Compute function selector (first 4 bytes of keccak256)
    fn compute_function_selector(&self, signature: &str) -> [u8; 4] {
        let mut hasher = Keccak256::new();
        hasher.update(signature.as_bytes());
        let hash = hasher.finalize();
        let mut selector = [0u8; 4];
        selector.copy_from_slice(&hash[..4]);
        selector
    }

    /// Generate transaction hash
    fn generate_tx_hash(&self, data: &[u8]) -> TxHash {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        hasher.update(&Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        let hash = hasher.finalize();
        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&hash);
        tx_hash
    }

    /// Simulate transaction confirmations
    async fn simulate_confirmations(&self, tx_hash: TxHash, _start_block: BlockNumber) {
        // In production, this would monitor the blockchain
        // For demo, we simulate immediate finality
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Update transaction status to finalized
        let mut history = self.tx_history.write();
        if let Some(tx) = history.iter_mut().find(|t| t.tx_hash == tx_hash) {
            tx.confirmations = MIN_CONFIRMATIONS;
            tx.status = TxStatus::Finalized;
        }
    }

    /// Get LC by ID
    pub fn get_lc(&self, lc_id: &Hash) -> Option<VerifiableLetterOfCredit> {
        self.active_lcs.read().get(lc_id).cloned()
    }

    /// Get LC by reference
    pub fn get_lc_by_reference(&self, reference: &str) -> Option<VerifiableLetterOfCredit> {
        self.active_lcs
            .read()
            .values()
            .find(|lc| lc.reference == reference)
            .cloned()
    }

    /// Get all active LCs
    pub fn get_all_lcs(&self) -> Vec<VerifiableLetterOfCredit> {
        self.active_lcs.read().values().cloned().collect()
    }

    /// Get transaction history
    pub fn get_transactions(&self) -> Vec<SettlementTransaction> {
        self.tx_history.read().clone()
    }

    /// Get transaction by hash
    pub fn get_transaction(&self, tx_hash: &TxHash) -> Option<SettlementTransaction> {
        self.tx_history
            .read()
            .iter()
            .find(|tx| &tx.tx_hash == tx_hash)
            .cloned()
    }

    /// Get settlement metrics
    pub fn get_metrics(&self) -> SettlementMetrics {
        let metrics = self.metrics.read();
        SettlementMetrics {
            total_lcs_minted: metrics.total_lcs_minted,
            total_value_settled_usd: metrics.total_value_settled_usd,
            avg_settlement_time_secs: metrics.avg_settlement_time_secs,
            total_gas_used: metrics.total_gas_used,
            failed_transactions: metrics.failed_transactions,
            disputes_raised: metrics.disputes_raised,
            disputes_resolved: metrics.disputes_resolved,
        }
    }

    /// Subscribe to settlement events
    pub fn subscribe<F>(&self, callback: F)
    where
        F: Fn(&SettlementEvent) + Send + Sync + 'static,
    {
        self.event_callbacks.write().push(Box::new(callback));
    }

    /// Emit an event
    fn emit_event(&self, event: SettlementEvent) {
        let callbacks = self.event_callbacks.read();
        for callback in callbacks.iter() {
            callback(&event);
        }
    }

    /// Get explorer URL for transaction
    pub fn get_explorer_url(&self, tx_hash: &TxHash) -> String {
        format!(
            "https://explorer.aethelred.org/tx/0x{}",
            hex::encode(tx_hash)
        )
    }

    /// Get explorer URL for LC
    pub fn get_lc_explorer_url(&self, lc_id: &Hash) -> String {
        format!("https://explorer.aethelred.org/lc/0x{}", hex::encode(lc_id))
    }
}

impl Default for SettlementEngine {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn create_test_proof(jurisdiction: Jurisdiction) -> VerificationProof {
        let now = Utc::now();
        let mut proof_bytes = vec![0u8; 256];
        // Add TEE marker
        proof_bytes[32..36].copy_from_slice(&[0x02, 0x00, 0x54, 0x45]);

        let mut hasher = Sha256::new();
        hasher.update(&proof_bytes);
        let hash = hasher.finalize();
        let mut proof_hash = [0u8; 32];
        proof_hash.copy_from_slice(&hash);

        VerificationProof {
            id: Uuid::new_v4(),
            proof_type: ProofType::SanctionsCheck,
            proof_bytes,
            proof_hash,
            generated_at: now,
            expires_at: now + Duration::hours(24),
            generating_node: format!("{}-tee-node-1", jurisdiction.node_region()),
            data_jurisdiction: jurisdiction,
            compliance_met: ComplianceStandard::for_jurisdiction(jurisdiction),
            verification_method: VerificationMethod::TeeEnclave,
            result_summary: ProofResultSummary {
                passed: true,
                confidence_score: 95,
                risk_level: RiskLevel::Low,
                summary_text: "All checks passed".to_string(),
                flags: vec![],
            },
        }
    }

    fn create_test_deal() -> TradeDeal {
        TradeDeal {
            id: Uuid::new_v4(),
            reference: "DEAL-001".to_string(),
            status: DealStatus::ReadyForLc,
            exporter: TradeParticipant {
                id: Uuid::new_v4(),
                legal_name: "UAE Solar Manufacturing Co.".to_string(),
                trading_name: None,
                registration_number: "UAE123456".to_string(),
                tax_id: Some("TAX123".to_string()),
                lei: Some("549300UAE00000SOLAR".to_string()),
                jurisdiction: Jurisdiction::Uae,
                bank: BankIdentifier::fab(),
                industry_code: "2610".to_string(),
                address: Address {
                    street_line_1: "Industrial City".to_string(),
                    street_line_2: None,
                    city: "Abu Dhabi".to_string(),
                    state_province: None,
                    postal_code: "00000".to_string(),
                    country_code: "AE".to_string(),
                },
                contact: ContactInfo {
                    primary_name: "Ahmed".to_string(),
                    primary_email: "ahmed@uaesolar.ae".to_string(),
                    primary_phone: "+971501234567".to_string(),
                    finance_email: None,
                },
                risk_rating: Some(RiskRating::A),
                sanctions_status: SanctionsStatus {
                    status: SanctionsResult::Clear,
                    screened_at: Utc::now(),
                    lists_checked: vec![SanctionsList::UnSc],
                    potential_matches: 0,
                    provider: "Aethelred".to_string(),
                },
                kyc_verified_at: Some(Utc::now()),
            },
            importer: TradeParticipant {
                id: Uuid::new_v4(),
                legal_name: "Singapore Construction Pte Ltd".to_string(),
                trading_name: None,
                registration_number: "SG987654".to_string(),
                tax_id: Some("TAXSG".to_string()),
                lei: Some("549300SG00000CONST".to_string()),
                jurisdiction: Jurisdiction::Singapore,
                bank: BankIdentifier::dbs(),
                industry_code: "4100".to_string(),
                address: Address {
                    street_line_1: "Marina Bay".to_string(),
                    street_line_2: None,
                    city: "Singapore".to_string(),
                    state_province: None,
                    postal_code: "018956".to_string(),
                    country_code: "SG".to_string(),
                },
                contact: ContactInfo {
                    primary_name: "Chen".to_string(),
                    primary_email: "chen@sgconstruction.sg".to_string(),
                    primary_phone: "+6512345678".to_string(),
                    finance_email: None,
                },
                risk_rating: Some(RiskRating::Aa),
                sanctions_status: SanctionsStatus {
                    status: SanctionsResult::Clear,
                    screened_at: Utc::now(),
                    lists_checked: vec![SanctionsList::UnSc],
                    potential_matches: 0,
                    provider: "Aethelred".to_string(),
                },
                kyc_verified_at: Some(Utc::now()),
            },
            exporter_bank: BankIdentifier::fab(),
            importer_bank: BankIdentifier::dbs(),
            goods_description: "Solar Panels 500W Monocrystalline".to_string(),
            quantity: "10,000 units".to_string(),
            unit_price: MonetaryAmount::usd(Decimal::from(500)),
            total_value: MonetaryAmount::usd(Decimal::from(5_000_000)),
            incoterms: Incoterms::Cif,
            letter_of_credit: None,
            guarantees: vec![],
            exporter_proofs: vec![],
            importer_proofs: vec![],
            settlement_proof: None,
            blockchain_status: BlockchainStatus {
                on_chain: false,
                network: "aethelred-mainnet".to_string(),
                contract_version: CONTRACT_VERSION.to_string(),
                last_block_height: None,
                confirmations: 0,
                finalized: false,
            },
            settlement_tx_hash: None,
            smart_contract_address: None,
            settlement_fees: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expected_completion: Utc::now() + Duration::days(30),
            completed_at: None,
            audit_trail: vec![],
        }
    }

    #[test]
    fn test_settlement_engine_creation() {
        let engine = SettlementEngine::new();
        assert!(!engine.contract_address_hex().is_empty());
        assert!(engine.contract_address_hex().starts_with("0x"));
    }

    #[tokio::test]
    async fn test_mint_letter_of_credit() {
        let engine = SettlementEngine::new();

        let exporter_proof = create_test_proof(Jurisdiction::Uae);
        let importer_proof = create_test_proof(Jurisdiction::Singapore);
        let deal = create_test_deal();

        let vlc = engine
            .mint_letter_of_credit(
                &exporter_proof,
                &importer_proof,
                &deal,
                &BankIdentifier::dbs(), // Issuing bank
                &BankIdentifier::fab(), // Advising bank
            )
            .await
            .unwrap();

        assert!(vlc.reference.starts_with("VLC-"));
        assert_eq!(vlc.status, OnChainLcStatus::Active);
        assert!(vlc.amount > 0);

        // Check metrics
        let metrics = engine.get_metrics();
        assert_eq!(metrics.total_lcs_minted, 1);
        assert!(metrics.total_value_settled_usd > 0);
    }

    #[test]
    fn test_proof_verification() {
        let engine = SettlementEngine::new();

        let valid_proof = create_test_proof(Jurisdiction::Uae);
        assert!(engine.verify_proof(&valid_proof).is_ok());

        // Test expired proof
        let mut expired_proof = create_test_proof(Jurisdiction::Uae);
        expired_proof.expires_at = Utc::now() - Duration::hours(1);
        assert!(engine.verify_proof(&expired_proof).is_err());
    }

    #[test]
    fn test_function_selector() {
        let engine = SettlementEngine::new();
        let selector = engine.compute_function_selector(
            "mintLetterOfCredit(bytes32,uint256,address,address,bytes,bytes)",
        );
        assert_eq!(selector.len(), 4);
    }
}
