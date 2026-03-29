#![no_main]
//! Fuzz target for Ethereum event parsing and bridge type deserialization.
//!
//! Exercises the address/hash parsing utilities and deposit ID generation
//! with arbitrary byte inputs. These functions are the first line of defence
//! when the bridge relayer ingests data from untrusted Ethereum JSON-RPC
//! responses, so they must never panic or exhibit undefined behaviour.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // -----------------------------------------------------------------------
    // 1. Fuzz hex-string address parsers with arbitrary UTF-8-ish input
    // -----------------------------------------------------------------------
    if let Ok(s) = std::str::from_utf8(data) {
        // parse_eth_address must return None (not panic) for any invalid input.
        let _ = aethelred_bridge::parse_eth_address(s);

        // parse_aethelred_address must return None (not panic) for any invalid input.
        let _ = aethelred_bridge::parse_aethelred_address(s);
    }

    // -----------------------------------------------------------------------
    // 2. Fuzz address-to-hex round-trip helpers
    // -----------------------------------------------------------------------
    if data.len() >= 20 {
        let mut eth_addr = [0u8; 20];
        eth_addr.copy_from_slice(&data[..20]);
        // eth_address_to_hex must never panic.
        let hex = aethelred_bridge::eth_address_to_hex(&eth_addr);
        // Round-trip: the hex output must parse back to the same address.
        let parsed = aethelred_bridge::parse_eth_address(&hex);
        assert_eq!(parsed, Some(eth_addr));
    }
    if data.len() >= 32 {
        let mut aethel_addr = [0u8; 32];
        aethel_addr.copy_from_slice(&data[..32]);
        let hex = aethelred_bridge::aethelred_address_to_hex(&aethel_addr);
        let parsed = aethelred_bridge::parse_aethelred_address(&hex);
        assert_eq!(parsed, Some(aethel_addr));
    }

    // -----------------------------------------------------------------------
    // 3. Fuzz EthereumDeposit construction and generate_id determinism
    // -----------------------------------------------------------------------
    // Build a deposit from raw bytes (minimum 128 bytes needed to fill all
    // fixed-size fields without panicking).
    if data.len() >= 128 {
        let mut depositor = [0u8; 20];
        depositor.copy_from_slice(&data[0..20]);

        let mut recipient = [0u8; 32];
        recipient.copy_from_slice(&data[20..52]);

        let mut token = [0u8; 20];
        token.copy_from_slice(&data[52..72]);

        let amount = u128::from_le_bytes(data[72..88].try_into().unwrap());
        let nonce = u64::from_le_bytes(data[88..96].try_into().unwrap());

        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&data[96..128]);

        // Avoid panics by ignoring remaining fields if data is too short.
        let log_index = if data.len() >= 124 {
            u32::from_le_bytes(data[120..124].try_into().unwrap())
        } else {
            0
        };

        let deposit = aethelred_bridge::EthereumDeposit {
            deposit_id: [0u8; 32],
            depositor,
            aethelred_recipient: recipient,
            token,
            amount,
            nonce,
            block_number: 0,
            block_hash: [0u8; 32],
            tx_hash,
            log_index,
            timestamp: 0,
        };

        // generate_id must be deterministic and must never panic.
        let id1 = deposit.generate_id();
        let id2 = deposit.generate_id();
        assert_eq!(id1, id2, "generate_id must be deterministic");
    }

    // -----------------------------------------------------------------------
    // 4. Fuzz RelayerSet consensus threshold calculations
    // -----------------------------------------------------------------------
    if data.len() >= 10 {
        let threshold_bps = u16::from_le_bytes([data[0], data[1]]);
        let relayer_count = (data[2] % 20) as usize; // cap at 20 relayers
        let vote_count = (data[3] % 25) as usize;

        let relayers: Vec<aethelred_bridge::RelayerIdentity> = (0..relayer_count)
            .map(|i| aethelred_bridge::RelayerIdentity {
                address: [i as u8; 32],
                eth_address: [i as u8; 20],
                public_key: vec![],
                stake: 1000,
                active: true,
            })
            .collect();

        let set = aethelred_bridge::RelayerSet {
            relayers,
            threshold_bps,
            version: 1,
            total_stake: relayer_count as u128 * 1000,
        };

        // These must never panic, even with extreme threshold values.
        let _ = set.min_votes_required();
        let _ = set.has_consensus(vote_count);
    }

    // -----------------------------------------------------------------------
    // 5. Fuzz JSON deserialization of deposit/burn types
    // -----------------------------------------------------------------------
    if let Ok(s) = std::str::from_utf8(data) {
        // Attempt to deserialize arbitrary JSON as bridge types.
        // Must return Err, never panic.
        let _ = serde_json::from_str::<aethelred_bridge::EthereumDeposit>(s);
        let _ = serde_json::from_str::<aethelred_bridge::AethelredBurn>(s);
        let _ = serde_json::from_str::<aethelred_bridge::MintProposal>(s);
        let _ = serde_json::from_str::<aethelred_bridge::WithdrawalProposal>(s);
        let _ = serde_json::from_str::<aethelred_bridge::RelayerSet>(s);
    }
});
