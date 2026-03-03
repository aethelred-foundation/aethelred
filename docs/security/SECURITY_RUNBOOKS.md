# Security Runbooks

**Version**: 1.0
**Status**: Active
**Last Updated**: 2026-02-28
**Owner**: Security Engineering / SRE

---

## 1. Runbook Index

| ID | Scenario | Severity | On-Call Action |
|----|----------|----------|----------------|
| SR-01 | Bridge mint rate limit exceeded | P1 High | Investigate, possibly pause bridge |
| SR-02 | VRF verification failure spike | P1 High | Check validator health, inspect proofs |
| SR-03 | Unauthorized key rotation attempt | P0 Critical | Verify timelock, alert governance |
| SR-04 | Consensus halt (no blocks produced) | P0 Critical | Validator coordination, emergency restart |
| SR-05 | Simulated verification on production chain | P0 Critical | Immediate investigation, possible chain halt |
| SR-06 | TEE attestation staleness | P2 Medium | Check enclave health, renew attestation |
| SR-07 | Ethereum reorg affecting bridge deposits | P1 High | Verify deposit status, re-confirm affected |
| SR-08 | Token supply anomaly detected | P0 Critical | Freeze bridge, audit all mints |
| SR-09 | Contract upgrade initiated | P1 High | Verify through governance, monitor execution |
| SR-10 | Guardian emergency pause triggered | P1 High | Assess threat, coordinate response |

---

## 2. SR-01: Bridge Mint Rate Limit Exceeded

### Detection
- Alert: `bridge_mint_rate_limit_exceeded` fires in Prometheus/PagerDuty
- Metric: `aethelred_bridge_current_window_minted > aethelred_bridge_max_mint_per_window`

### Diagnosis
```bash
# Check current rate limit state
cast call $BRIDGE_ADDRESS "currentWindowMinted()(uint256)" --rpc-url $RPC
cast call $BRIDGE_ADDRESS "maxMintPerWindow()(uint256)" --rpc-url $RPC
cast call $BRIDGE_ADDRESS "windowStart()(uint256)" --rpc-url $RPC

# Check recent mint transactions
cast logs --address $BRIDGE_ADDRESS \
    "TokensMinted(address,uint256,bytes32)" \
    --from-block $(($(cast block-number) - 1000)) --rpc-url $RPC
```

### Response
1. **If legitimate high volume**: Window will reset naturally. Monitor.
2. **If suspicious**: Trigger guardian emergency pause via multi-sig.
3. **Escalate** to security team if pattern appears malicious.

### Resolution
- Clear expired rate limit state: `clearExpiredRateLimitState()`
- If pause triggered, require governance vote to unpause.

---

## 3. SR-02: VRF Verification Failure Spike

### Detection
- Alert: `vrf_verification_failure_rate > 5%` over 10 minutes
- Metric: `aethelred_consensus_vrf_failures_total`

### Diagnosis
```bash
# Check validator logs for VRF errors
journalctl -u aethelred-node --since "10 minutes ago" | grep -i "vrf\|verification"

# Check if specific validator is failing
curl localhost:26660/metrics | grep vrf_verification

# Inspect recent proof submissions
aethelred query consensus vrf-stats --node tcp://localhost:26657
```

### Response
1. **Single validator failing**: Contact validator operator, likely key/config issue.
2. **Multiple validators failing**: Check for network-wide issue (clock drift, software bug).
3. **All validators failing**: Emergency — possible consensus-breaking bug. Coordinate halt.

### Resolution
- Validator re-derives epoch keys: `aethelred keys derive-epoch --epoch <N>`
- If widespread, coordinate software upgrade via governance.

---

## 4. SR-03: Unauthorized Key Rotation Attempt

### Detection
- Alert: `governance_key_rotation_attempted` with unexpected parameters
- Event: `KeyRotationQueued` emitted from SovereignGovernanceTimelock

### Diagnosis
```bash
# Check pending timelock operations
cast call $TIMELOCK_ADDRESS "getMinDelay()(uint256)" --rpc-url $RPC

# Inspect the queued operation
cast logs --address $TIMELOCK_ADDRESS \
    "KeyRotationQueued(bytes32,address,uint8,address,uint256)" \
    --from-block $(($(cast block-number) - 100)) --rpc-url $RPC

# Verify signatures are from expected governance keys
cast call $BRIDGE_ADDRESS "issuerGovernanceKey()(address)" --rpc-url $RPC
cast call $BRIDGE_ADDRESS "foundationGovernanceKey()(address)" --rpc-url $RPC
```

### Response
1. **If authorized**: Verify with Issuer and Foundation key holders. Monitor execution.
2. **If unauthorized**: Cancel the operation before timelock expires (7-day window).
3. **If keys compromised**: Trigger emergency key rotation via recovery governance key.

### Resolution
- Cancel via timelock: `cancel(operationId)`
- If compromise confirmed, execute emergency key rotation procedure.

---

## 5. SR-04: Consensus Halt

### Detection
- Alert: `block_production_stalled` — no new block in > 30 seconds (5x block time)
- Metric: `cometbft_consensus_latest_block_height` not incrementing

### Diagnosis
```bash
# Check node status
curl localhost:26657/status | jq '.result.sync_info'

# Check validator connectivity
curl localhost:26657/net_info | jq '.result.n_peers'

# Check consensus state
curl localhost:26657/dump_consensus_state | jq '.result.round_state'

# Check for panics in logs
journalctl -u aethelred-node --since "5 minutes ago" | grep -i "panic\|fatal\|CONSENSUS FAILURE"
```

### Response
1. **< 1/3 validators offline**: Wait for recovery, consensus should resume.
2. **> 1/3 validators offline**: Coordinate restart, verify network partition.
3. **Software bug**: Coordinate emergency patch across validators.
4. **Never** force-push state or skip validation — follow BFT recovery procedures.

### Resolution
- Restart affected validators: `systemctl restart aethelred-node`
- If state corruption: restore from latest snapshot, replay from checkpoint.

---

## 6. SR-08: Token Supply Anomaly

### Detection
- Alert: `token_supply_anomaly` — `totalSupply()` differs from expected constant
- Metric: `aethelred_token_total_supply != 10_000_000_000e18`

### Diagnosis
```bash
# Verify total supply
cast call $TOKEN_ADDRESS "totalSupply()(uint256)" --rpc-url $RPC

# Check bridge mint/burn totals
cast call $BRIDGE_ADDRESS "totalMinted()(uint256)" --rpc-url $RPC

# Check for unexpected mint events
cast logs --address $TOKEN_ADDRESS \
    "Transfer(address,address,uint256)" \
    --from-block 0 --rpc-url $RPC | grep "from: 0x0000"
```

### Response
1. **Immediately** pause the bridge via guardian multi-sig.
2. **Freeze** affected addresses via compliance role.
3. **Audit** all mint transactions for unauthorized issuance.
4. **Escalate** to security team and legal.

### Resolution
- If bridge exploit: fix vulnerability, deploy upgrade via governance.
- If token contract bug: deploy upgraded implementation via UUPS proxy.
- Coordinate with exchanges for potential rollback coordination.

---

## 7. Upgrade Procedures

### 7.1 Smart Contract Upgrade (UUPS Proxy)

**Pre-upgrade Checklist:**
- [ ] Upgrade has passed full audit review
- [ ] Storage layout compatibility verified (no slot collisions)
- [ ] `__gap` slots sufficient for new storage variables
- [ ] All tests pass on fork of mainnet state
- [ ] Governance proposal approved (7-day timelock)
- [ ] Rollback plan documented and tested

**Execution:**
```bash
# 1. Deploy new implementation
forge script scripts/DeployUpgrade.s.sol --rpc-url $RPC --broadcast

# 2. Verify on explorer
forge verify-contract $NEW_IMPL_ADDRESS AethelredBridgeV2 --chain-id 1

# 3. Execute upgrade via timelock (already scheduled by governance)
cast send $TIMELOCK_ADDRESS "execute(address,uint256,bytes,bytes32,bytes32)" \
    $PROXY_ADDRESS 0 $UPGRADE_CALLDATA $PREDECESSOR $SALT \
    --rpc-url $RPC --private-key $EXECUTOR_KEY

# 4. Verify upgrade
cast call $PROXY_ADDRESS "version()(string)" --rpc-url $RPC
# Expected: "2.0.0"
```

**Post-upgrade Verification:**
- [ ] `version()` returns expected version
- [ ] All existing state is accessible
- [ ] New functions work correctly
- [ ] Monitoring shows no anomalies

### 7.2 Cosmos SDK Module Upgrade

**Execution:**
```bash
# 1. Create governance proposal for software upgrade
aethelred tx gov submit-proposal software-upgrade v2.0.0 \
    --upgrade-height $TARGET_HEIGHT \
    --title "v2.0.0 Security Upgrade" \
    --description "Addresses audit findings RS-01 through RS-07" \
    --from governance \
    --chain-id aethelred-1

# 2. Vote
aethelred tx gov vote $PROPOSAL_ID yes --from validator

# 3. At upgrade height, node halts. Replace binary:
systemctl stop aethelred-node
cp aethelred-node-v2.0.0 /usr/local/bin/aethelred-node
systemctl start aethelred-node

# 4. Verify
aethelred version  # Expected: v2.0.0
```

---

## 8. Emergency Contacts

| Role | Contact | Escalation Time |
|------|---------|-----------------|
| Security On-Call | security-oncall@aethelred.io | Immediate |
| Engineering Lead | eng-lead@aethelred.io | 15 minutes |
| CTO | cto@aethelred.io | 30 minutes |
| Legal | legal@aethelred.io | 1 hour |
| Communications | comms@aethelred.io | 1 hour |
| Bug Bounty | security@aethelred.io | 24 hours |
