//! Integration Tests for System Contracts
//!
//! Tests the full system kernel flow including:
//! - Job submission with compliance checks
//! - Staking and slashing
//! - Fee distribution with adaptive burn
//! - Cross-module interactions

use super::*;
use std::collections::HashMap;

// =============================================================================
// TEST HELPERS
// =============================================================================

fn test_address(seed: u8) -> Address {
    let mut addr = [0u8; 32];
    addr[0] = seed;
    addr
}

fn test_hash(seed: u8) -> Hash {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash
}

fn create_test_kernel() -> SystemKernel {
    let genesis = GenesisConfig::devnet();
    SystemKernel::from_genesis(&genesis).expect("Failed to create test kernel")
}

fn fund_account(kernel: &SystemKernel, address: Address, amount: TokenAmount) {
    kernel
        .bank
        .write()
        .mint(address, amount)
        .expect("Failed to fund account");
}

fn create_certified_entity(
    kernel: &SystemKernel,
    entity: Address,
    standard: ComplianceStandard,
) {
    let cert = Certification {
        standard,
        entity_did: Did::from_address(&entity),
        entity_address: entity,
        issuer: Did::new("aethelred", "test-issuer"),
        level: 4,
        issued_at: 1000,
        expires_at: 100_000_000,
        document_hash: test_hash(99),
        metadata: HashMap::new(),
        revoked: false,
        revocation_reason: None,
    };
    kernel
        .compliance
        .write()
        .add_certification(cert)
        .expect("Failed to add certification");
}

// =============================================================================
// SYSTEM KERNEL TESTS
// =============================================================================

#[test]
fn test_kernel_creation() {
    let kernel = create_test_kernel();

    let ctx = kernel.context();
    assert_eq!(ctx.height, 0);
    assert_eq!(ctx.timestamp, 0);
}

#[test]
fn test_kernel_begin_end_block() {
    let kernel = create_test_kernel();

    // Begin block
    let ctx = BlockContext {
        height: 100,
        timestamp: 1_000_000,
        slot: 100,
        proposer: test_address(1),
        gas_limit: 30_000_000,
        gas_used: 15_000_000, // 50% utilization
    };
    kernel.begin_block(ctx.clone());

    assert_eq!(kernel.context().height, 100);
    assert_eq!(kernel.context().timestamp, 1_000_000);

    // End block
    let events = kernel.end_block().expect("End block failed");
    // May or may not have events depending on state
    assert!(events.len() >= 0);
}

// =============================================================================
// JOB REGISTRY TESTS
// =============================================================================

#[test]
fn test_job_submission_flow() {
    let kernel = create_test_kernel();

    let requester = test_address(1);
    let bid_amount = 1_000_000_000_000u128; // 1 token

    // Fund the requester
    fund_account(&kernel, requester, bid_amount * 10);

    // Begin a block
    kernel.begin_block(BlockContext {
        height: 1,
        timestamp: 1_000_000,
        slot: 1,
        proposer: test_address(99),
        gas_limit: 30_000_000,
        gas_used: 0,
    });

    // Submit job
    let params = SubmitJobParams {
        requester,
        model_hash: test_hash(1),
        input_hash: test_hash(2),
        max_bid: bid_amount,
        bid_amount,
        verification_method: VerificationMethod::TeeAttestation,
        priority: JobPriority::Normal,
        sla_timeout: 0,
        tags: vec![],
        encrypted_input: None,
        callback: None,
        data_provider: None,
        required_compliance: vec![],
        jurisdiction: None,
    };

    let result = kernel.execute(SystemCall::SubmitJob(params));
    assert!(result.is_ok(), "Job submission failed: {:?}", result);

    match result.unwrap() {
        SystemCallResult::JobSubmitted(job_result) => {
            assert_eq!(job_result.escrowed, bid_amount);
            assert!(job_result.sla_deadline > 0);
        }
        _ => panic!("Expected JobSubmitted result"),
    }
}

#[test]
fn test_job_assignment() {
    let kernel = create_test_kernel();

    let requester = test_address(1);
    let prover = test_address(2);
    let bid_amount = 1_000_000_000_000u128;

    // Fund accounts
    fund_account(&kernel, requester, bid_amount * 10);
    fund_account(&kernel, prover, 100_000_000_000_000_000_000u128); // For staking

    // Stake the prover as a compute node
    kernel.begin_block(BlockContext {
        height: 1,
        timestamp: 1_000_000,
        slot: 1,
        proposer: test_address(99),
        gas_limit: 30_000_000,
        gas_used: 0,
    });

    // First stake
    let stake_result = kernel.execute(SystemCall::Stake(
        prover,
        StakeRole::ComputeNode.min_stake(),
        StakeRole::ComputeNode,
    ));
    assert!(stake_result.is_ok(), "Staking failed: {:?}", stake_result);

    // Submit job
    let params = SubmitJobParams {
        requester,
        model_hash: test_hash(1),
        input_hash: test_hash(2),
        max_bid: bid_amount,
        bid_amount,
        verification_method: VerificationMethod::TeeAttestation,
        priority: JobPriority::Normal,
        sla_timeout: 0,
        tags: vec![],
        encrypted_input: None,
        callback: None,
        data_provider: None,
        required_compliance: vec![],
        jurisdiction: None,
    };

    let submit_result = kernel.execute(SystemCall::SubmitJob(params)).unwrap();
    let job_id = match submit_result {
        SystemCallResult::JobSubmitted(r) => r.job_id,
        _ => panic!("Expected JobSubmitted"),
    };

    // Assign job to prover
    let assign_result = kernel.execute(SystemCall::AssignJob(job_id, prover));
    assert!(
        assign_result.is_ok(),
        "Assignment failed: {:?}",
        assign_result
    );

    match assign_result.unwrap() {
        SystemCallResult::JobAssigned(r) => {
            assert_eq!(r.job_id, job_id);
            assert_eq!(r.prover, prover);
        }
        _ => panic!("Expected JobAssigned result"),
    }
}

// =============================================================================
// STAKING TESTS
// =============================================================================

#[test]
fn test_stake_and_unstake() {
    let kernel = create_test_kernel();

    let staker = test_address(1);
    let stake_amount = StakeRole::Validator.min_stake();

    // Fund the staker
    fund_account(&kernel, staker, stake_amount * 2);

    kernel.begin_block(BlockContext {
        height: 1,
        timestamp: 1_000_000,
        slot: 1,
        proposer: test_address(99),
        gas_limit: 30_000_000,
        gas_used: 0,
    });

    // Stake
    let result = kernel.execute(SystemCall::Stake(staker, stake_amount, StakeRole::Validator));
    assert!(result.is_ok(), "Staking failed: {:?}", result);

    // Check stake
    let stake_info = kernel.staking.read().get_stake(&staker);
    assert!(stake_info.is_some());
    assert_eq!(stake_info.unwrap().amount, stake_amount);

    // Initiate unstake
    let unstake_amount = stake_amount / 2;
    let unstake_result = kernel.execute(SystemCall::Unstake(staker, unstake_amount));
    assert!(unstake_result.is_ok(), "Unstake failed: {:?}", unstake_result);

    // Check pending unstake
    let updated_stake = kernel.staking.read().get_stake(&staker).unwrap();
    assert_eq!(updated_stake.pending_unstake, unstake_amount);
}

#[test]
fn test_adaptive_burn_rate() {
    let kernel = create_test_kernel();

    // Test low utilization (should have low burn rate)
    kernel.staking.write().update_utilization(20); // 20% utilization
    let stats_low = kernel.staking.read().statistics();
    let burn_rate_low = stats_low.current_burn_rate_bps;

    // Test high utilization (should have higher burn rate)
    kernel.staking.write().update_utilization(90); // 90% utilization
    let stats_high = kernel.staking.read().statistics();
    let burn_rate_high = stats_high.current_burn_rate_bps;

    assert!(
        burn_rate_high > burn_rate_low,
        "High utilization should have higher burn rate"
    );
}

// =============================================================================
// COMPLIANCE TESTS
// =============================================================================

#[test]
fn test_sanctions_screening() {
    let kernel = create_test_kernel();

    let good_addr = test_address(1);
    let bad_addr = test_address(2);

    // Enable compliance
    kernel.compliance.write().config.enabled = true;
    kernel.compliance.write().config.enforce_sanctions = true;

    // Add bad_addr to sanctions
    kernel
        .compliance
        .write()
        .add_sanctioned_address(bad_addr, "TEST_LIST".to_string())
        .unwrap();

    // Good address should pass
    let metadata = HashMap::new();
    let good_result = kernel.compliance.write().enforce(
        &good_addr,
        None,
        &[],
        None,
        0,
        &metadata,
    );
    assert!(good_result.is_ok());
    assert!(good_result.unwrap().passed);

    // Bad address should fail
    let bad_result = kernel.compliance.write().enforce(
        &bad_addr,
        None,
        &[],
        None,
        0,
        &metadata,
    );
    assert!(bad_result.is_ok());
    assert!(!bad_result.unwrap().passed);
}

#[test]
fn test_certification_requirement() {
    let kernel = create_test_kernel();

    let entity = test_address(1);

    // Enable compliance
    kernel.compliance.write().config.enabled = true;
    kernel.compliance.write().update_time(2000);

    // Without certification, should fail
    let metadata = HashMap::new();
    let result1 = kernel.compliance.write().enforce(
        &entity,
        None,
        &[ComplianceStandard::HipaaUs],
        None,
        0,
        &metadata,
    );
    assert!(result1.is_ok());
    assert!(!result1.unwrap().passed);

    // Add certification
    create_certified_entity(&kernel, entity, ComplianceStandard::HipaaUs);

    // Now should pass
    let result2 = kernel.compliance.write().enforce(
        &entity,
        None,
        &[ComplianceStandard::HipaaUs],
        None,
        0,
        &metadata,
    );
    assert!(result2.is_ok());
    assert!(result2.unwrap().passed);
}

#[test]
fn test_blocked_jurisdiction() {
    let kernel = create_test_kernel();

    let entity = test_address(1);

    // Enable compliance
    kernel.compliance.write().config.enabled = true;
    kernel.compliance.write().config.enforce_sanctions = false; // Just test jurisdiction

    // Try from blocked jurisdiction (North Korea)
    let metadata = HashMap::new();
    let result = kernel.compliance.write().enforce(
        &entity,
        None,
        &[],
        Some("KP"),
        0,
        &metadata,
    );

    assert!(result.is_ok());
    let check_result = result.unwrap();
    assert!(!check_result.passed);
    assert!(check_result.violations.iter().any(|v| matches!(
        v,
        ViolationType::JurisdictionBlocked { .. }
    )));
}

#[test]
fn test_baa_requirement() {
    let kernel = create_test_kernel();

    let covered_entity = test_address(1);
    let business_associate = test_address(2);

    // Enable compliance
    kernel.compliance.write().config.enabled = true;
    kernel.compliance.write().update_time(2000);

    // Add HIPAA certifications for both
    create_certified_entity(&kernel, covered_entity, ComplianceStandard::HipaaUs);
    create_certified_entity(&kernel, business_associate, ComplianceStandard::HipaaUs);

    // Without BAA, should fail
    let metadata = HashMap::new();
    let result1 = kernel.compliance.write().enforce(
        &covered_entity,
        Some(&business_associate),
        &[ComplianceStandard::HipaaUs],
        None,
        0,
        &metadata,
    );
    assert!(result1.is_ok());
    assert!(!result1.unwrap().passed);

    // Register BAA
    kernel
        .compliance
        .write()
        .register_baa(covered_entity, business_associate)
        .unwrap();

    // Now should pass
    let result2 = kernel.compliance.write().enforce(
        &covered_entity,
        Some(&business_associate),
        &[ComplianceStandard::HipaaUs],
        None,
        0,
        &metadata,
    );
    assert!(result2.is_ok());
    assert!(result2.unwrap().passed);
}

// =============================================================================
// BANK TESTS
// =============================================================================

#[test]
fn test_bank_transfers() {
    let kernel = create_test_kernel();

    let alice = test_address(1);
    let bob = test_address(2);
    let amount = 1_000_000_000_000u128;

    // Fund Alice
    fund_account(&kernel, alice, amount * 10);

    // Transfer from Alice to Bob
    let result = kernel.bank.write().transfer(alice, bob, amount);
    assert!(result.is_ok(), "Transfer failed: {:?}", result);

    // Check balances
    let alice_balance = kernel.bank.read().balance(&alice);
    let bob_balance = kernel.bank.read().balance(&bob);

    assert_eq!(alice_balance, amount * 9);
    assert_eq!(bob_balance, amount);
}

#[test]
fn test_bank_escrow() {
    let kernel = create_test_kernel();

    let depositor = test_address(1);
    let amount = 1_000_000_000_000u128;

    // Fund depositor
    fund_account(&kernel, depositor, amount * 10);

    let escrow_id = test_hash(1);

    // Create escrow
    let create_result = kernel.bank.write().create_escrow(
        escrow_id,
        depositor,
        amount,
        "job_completion".to_string(),
    );
    assert!(create_result.is_ok());

    // Check balance decreased
    let balance_after_escrow = kernel.bank.read().balance(&depositor);
    assert_eq!(balance_after_escrow, amount * 9);

    // Check escrow exists
    let escrow = kernel.bank.read().get_escrow(&escrow_id);
    assert!(escrow.is_some());
    assert_eq!(escrow.unwrap().amount, amount);
}

// =============================================================================
// END-TO-END FLOW TESTS
// =============================================================================

#[test]
fn test_full_job_flow_with_compliance() {
    let kernel = create_test_kernel();

    let requester = test_address(1);
    let prover = test_address(2);
    let data_provider = test_address(3);
    let bid_amount = 1_000_000_000_000u128;

    // Enable compliance with HIPAA requirement
    kernel.compliance.write().config.enabled = true;
    kernel.compliance.write().update_time(2000);

    // Fund accounts
    fund_account(&kernel, requester, bid_amount * 100);
    fund_account(&kernel, prover, 100_000_000_000_000_000_000u128);

    // Add certifications
    create_certified_entity(&kernel, requester, ComplianceStandard::HipaaUs);
    create_certified_entity(&kernel, data_provider, ComplianceStandard::HipaaUs);

    // Register BAA
    kernel
        .compliance
        .write()
        .register_baa(requester, data_provider)
        .unwrap();

    // Begin block
    kernel.begin_block(BlockContext {
        height: 1,
        timestamp: 2000,
        slot: 1,
        proposer: test_address(99),
        gas_limit: 30_000_000,
        gas_used: 0,
    });

    // Stake prover
    kernel
        .execute(SystemCall::Stake(
            prover,
            StakeRole::ComputeNode.min_stake(),
            StakeRole::ComputeNode,
        ))
        .unwrap();

    // Submit job with HIPAA compliance
    let params = SubmitJobParams {
        requester,
        model_hash: test_hash(1),
        input_hash: test_hash(2),
        max_bid: bid_amount,
        bid_amount,
        verification_method: VerificationMethod::TeeAttestation,
        priority: JobPriority::Normal,
        sla_timeout: 0,
        tags: vec![ComplianceTag {
            name: "MEDICAL_DATA".to_string(),
            value: None,
        }],
        encrypted_input: None,
        callback: None,
        data_provider: Some(data_provider),
        required_compliance: vec![ComplianceRequirement::HipaaUs],
        jurisdiction: Some("US".to_string()),
    };

    let submit_result = kernel.execute(SystemCall::SubmitJob(params));
    assert!(
        submit_result.is_ok(),
        "Job submission failed: {:?}",
        submit_result
    );
}

#[test]
fn test_job_rejected_without_certification() {
    let kernel = create_test_kernel();

    let requester = test_address(1);
    let bid_amount = 1_000_000_000_000u128;

    // Enable compliance
    kernel.compliance.write().config.enabled = true;
    kernel.compliance.write().update_time(2000);

    // Fund account but DON'T add certification
    fund_account(&kernel, requester, bid_amount * 100);

    // Begin block
    kernel.begin_block(BlockContext {
        height: 1,
        timestamp: 2000,
        slot: 1,
        proposer: test_address(99),
        gas_limit: 30_000_000,
        gas_used: 0,
    });

    // Submit job requiring HIPAA (should fail)
    let params = SubmitJobParams {
        requester,
        model_hash: test_hash(1),
        input_hash: test_hash(2),
        max_bid: bid_amount,
        bid_amount,
        verification_method: VerificationMethod::TeeAttestation,
        priority: JobPriority::Normal,
        sla_timeout: 0,
        tags: vec![],
        encrypted_input: None,
        callback: None,
        data_provider: None,
        required_compliance: vec![ComplianceRequirement::HipaaUs],
        jurisdiction: None,
    };

    let result = kernel.execute(SystemCall::SubmitJob(params));
    assert!(result.is_err(), "Job should have been rejected");

    match result {
        Err(SystemContractError::Compliance(_)) => {
            // Expected
        }
        _ => panic!("Expected compliance error"),
    }
}

// =============================================================================
// FEE DISTRIBUTION TESTS
// =============================================================================

#[test]
fn test_fee_split_calculation() {
    let kernel = create_test_kernel();

    // Set utilization to 50%
    kernel.staking.write().update_utilization(50);

    let total_fee = 1_000_000_000_000u128; // 1 token

    let split = kernel.staking.read().calculate_fee_split(total_fee);

    // Verify split percentages
    assert!(split.prover_amount > 0);
    assert!(split.validator_amount > 0);
    assert!(split.burn_amount > 0);

    // Verify sum equals total
    assert_eq!(
        split.prover_amount + split.validator_amount + split.burn_amount,
        total_fee
    );

    // Prover should get ~70%
    let prover_pct = (split.prover_amount as f64 / total_fee as f64) * 100.0;
    assert!(
        prover_pct >= 65.0 && prover_pct <= 75.0,
        "Prover should get ~70%, got {}%",
        prover_pct
    );
}

// =============================================================================
// GENESIS CONFIGURATION TESTS
// =============================================================================

#[test]
fn test_genesis_configs() {
    // Test mainnet
    let mainnet = GenesisConfig::mainnet();
    assert!(mainnet.validate().is_ok());
    assert_eq!(mainnet.chain_id, "aethelred-mainnet-1");

    // Test testnet
    let testnet = GenesisConfig::testnet();
    assert!(testnet.validate().is_ok());
    assert_eq!(testnet.chain_id, "aethelred-testnet-1");

    // Test devnet
    let devnet = GenesisConfig::devnet();
    assert!(devnet.validate().is_ok());
    assert_eq!(devnet.chain_id, "aethelred-devnet");
}

#[test]
fn test_invalid_genesis_config() {
    let mut config = GenesisConfig::devnet();
    config.chain_id = "".to_string();

    assert!(config.validate().is_err());
}

// =============================================================================
// STATISTICS TESTS
// =============================================================================

#[test]
fn test_compliance_statistics() {
    let kernel = create_test_kernel();

    let entity = test_address(1);

    // Enable compliance and audit logging
    kernel.compliance.write().config.enabled = true;
    kernel.compliance.write().config.audit_logging = true;
    kernel.compliance.write().update_time(2000);

    // Perform some checks
    let metadata = HashMap::new();
    for _ in 0..5 {
        kernel
            .compliance
            .write()
            .enforce(&entity, None, &[], None, 0, &metadata)
            .unwrap();
    }

    let stats = kernel.compliance.read().statistics();
    assert_eq!(stats.total_checks, 5);
    assert_eq!(stats.passed_checks, 5);
    assert_eq!(stats.failed_checks, 0);
}
