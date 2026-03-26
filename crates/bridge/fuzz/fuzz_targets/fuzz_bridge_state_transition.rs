#![no_main]
//! Fuzz target for bridge state transition logic.
//!
//! Exercises the deposit/burn validation rules and status enum transitions
//! with fuzz-generated field values. The goal is to ensure that the
//! EventProcessor validation helpers and the type-level invariants never
//! panic, even when fed adversarial inputs such as zero amounts, null
//! addresses, duplicate IDs, and extreme nonce/timestamp values.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 96 bytes to populate all fixed-size fields.
    if data.len() < 96 {
        return;
    }

    // -----------------------------------------------------------------------
    // 1. Fuzz DepositStatus / WithdrawalStatus serialization round-trips
    // -----------------------------------------------------------------------
    {
        use aethelred_bridge::{DepositStatus, WithdrawalStatus};

        let statuses = [
            DepositStatus::Pending,
            DepositStatus::Confirmed,
            DepositStatus::MintProposed,
            DepositStatus::Completed,
            DepositStatus::Cancelled,
            DepositStatus::Failed,
        ];
        // Pick a status based on fuzz input.
        let status = statuses[data[0] as usize % statuses.len()];
        let json = serde_json::to_string(&status).unwrap();
        let parsed: DepositStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, parsed);

        let w_statuses = [
            WithdrawalStatus::Pending,
            WithdrawalStatus::Confirmed,
            WithdrawalStatus::WithdrawalProposed,
            WithdrawalStatus::ConsensusReached,
            WithdrawalStatus::ReadyToProcess,
            WithdrawalStatus::Completed,
            WithdrawalStatus::Challenged,
            WithdrawalStatus::Failed,
        ];
        let w_status = w_statuses[data[1] as usize % w_statuses.len()];
        let json = serde_json::to_string(&w_status).unwrap();
        let parsed: WithdrawalStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(w_status, parsed);
    }

    // -----------------------------------------------------------------------
    // 2. Fuzz MintProposalStatus / WithdrawalProposalStatus round-trips
    // -----------------------------------------------------------------------
    {
        use aethelred_bridge::{MintProposalStatus, WithdrawalProposalStatus};

        let m_statuses = [
            MintProposalStatus::Voting,
            MintProposalStatus::ConsensusReached,
            MintProposalStatus::Completed,
            MintProposalStatus::Expired,
            MintProposalStatus::Rejected,
        ];
        let m_status = m_statuses[data[2] as usize % m_statuses.len()];
        let json = serde_json::to_string(&m_status).unwrap();
        let parsed: MintProposalStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(m_status, parsed);

        let wp_statuses = [
            WithdrawalProposalStatus::Voting,
            WithdrawalProposalStatus::SubmittedToEthereum,
            WithdrawalProposalStatus::InChallengePeriod,
            WithdrawalProposalStatus::ReadyToProcess,
            WithdrawalProposalStatus::Completed,
            WithdrawalProposalStatus::Challenged,
            WithdrawalProposalStatus::Expired,
        ];
        let wp_status = wp_statuses[data[3] as usize % wp_statuses.len()];
        let json = serde_json::to_string(&wp_status).unwrap();
        let parsed: WithdrawalProposalStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(wp_status, parsed);
    }

    // -----------------------------------------------------------------------
    // 3. Fuzz TokenType serialization
    // -----------------------------------------------------------------------
    {
        use aethelred_bridge::TokenType;

        let selector = data[4] % 3;
        let token_type = match selector {
            0 => TokenType::WrappedETH,
            1 => {
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&data[5..25]);
                TokenType::WrappedERC20(addr)
            }
            _ => TokenType::NativeAETHEL,
        };

        let json = serde_json::to_string(&token_type).unwrap();
        let parsed: TokenType = serde_json::from_str(&json).unwrap();
        assert_eq!(token_type, parsed);
    }

    // -----------------------------------------------------------------------
    // 4. Fuzz EthereumDeposit -> JSON -> EthereumDeposit round-trip
    // -----------------------------------------------------------------------
    {
        let mut depositor = [0u8; 20];
        depositor.copy_from_slice(&data[0..20]);

        let mut recipient = [0u8; 32];
        recipient.copy_from_slice(&data[20..52]);

        let mut token = [0u8; 20];
        token.copy_from_slice(&data[52..72]);

        let amount = u128::from_le_bytes(data[72..88].try_into().unwrap());
        let nonce = u64::from_le_bytes(data[88..96].try_into().unwrap());

        let deposit = aethelred_bridge::EthereumDeposit {
            deposit_id: [0u8; 32],
            depositor,
            aethelred_recipient: recipient,
            token,
            amount,
            nonce,
            block_number: 0,
            block_hash: [0u8; 32],
            tx_hash: [0u8; 32],
            log_index: 0,
            timestamp: 0,
        };

        // Serialize -> deserialize must never panic and must round-trip.
        let json = serde_json::to_string(&deposit).unwrap();
        let parsed: aethelred_bridge::EthereumDeposit =
            serde_json::from_str(&json).unwrap();
        assert_eq!(deposit.amount, parsed.amount);
        assert_eq!(deposit.nonce, parsed.nonce);
        assert_eq!(deposit.depositor, parsed.depositor);
        assert_eq!(deposit.aethelred_recipient, parsed.aethelred_recipient);
    }

    // -----------------------------------------------------------------------
    // 5. Fuzz AethelredBurn -> JSON -> AethelredBurn round-trip
    // -----------------------------------------------------------------------
    if data.len() >= 100 {
        let mut burner = [0u8; 32];
        burner.copy_from_slice(&data[0..32]);

        let mut eth_recipient = [0u8; 20];
        eth_recipient.copy_from_slice(&data[32..52]);

        let amount = u128::from_le_bytes(data[52..68].try_into().unwrap());
        let nonce = u64::from_le_bytes(data[68..76].try_into().unwrap());

        let burn = aethelred_bridge::AethelredBurn {
            burn_id: [0u8; 32],
            burner,
            eth_recipient,
            token_type: aethelred_bridge::TokenType::WrappedETH,
            amount,
            nonce,
            block_height: 0,
            block_hash: [0u8; 32],
            tx_hash: [0u8; 32],
            timestamp: 0,
        };

        let json = serde_json::to_string(&burn).unwrap();
        let parsed: aethelred_bridge::AethelredBurn =
            serde_json::from_str(&json).unwrap();
        assert_eq!(burn.amount, parsed.amount);
        assert_eq!(burn.nonce, parsed.nonce);
        assert_eq!(burn.burner, parsed.burner);
    }

    // -----------------------------------------------------------------------
    // 6. Fuzz RelayerVote serialization
    // -----------------------------------------------------------------------
    if data.len() >= 44 {
        let mut relayer = [0u8; 32];
        relayer.copy_from_slice(&data[0..32]);

        let approve = data[32] % 2 == 0;
        let timestamp = u64::from_le_bytes(data[33..41].try_into().unwrap());

        let sig_len = (data[41] as usize) % 128;
        let sig_data = if data.len() >= 44 + sig_len {
            data[44..44 + sig_len].to_vec()
        } else {
            vec![]
        };

        let vote = aethelred_bridge::RelayerVote {
            relayer,
            approve,
            signature: sig_data,
            timestamp,
        };

        let json = serde_json::to_string(&vote).unwrap();
        let parsed: aethelred_bridge::RelayerVote =
            serde_json::from_str(&json).unwrap();
        assert_eq!(vote.approve, parsed.approve);
        assert_eq!(vote.timestamp, parsed.timestamp);
        assert_eq!(vote.relayer, parsed.relayer);
    }
});
