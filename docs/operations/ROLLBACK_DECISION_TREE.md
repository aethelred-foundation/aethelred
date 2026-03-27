# Rollback Decision Tree

**Version:** 1.0
**Status:** Active
**Owner:** SRE / Launch Operations
**Last Updated:** 2026-03-25
**Classification:** Internal -- Operator + SRE + Security

---

## 1. Purpose

This document provides a structured decision framework for determining when and how to perform rollbacks during the Aethelred mainnet launch and ongoing operations. Every on-call engineer must be familiar with this tree before launch.

---

## 2. Decision Tree Overview

```
Incident Detected
       |
       v
+------------------+
| Is the chain     |     YES
| producing blocks?|-----------> Go to Section 4 (Non-Halt Issues)
+------------------+
       | NO
       v
+------------------+
| Has consensus    |     YES
| been halted      |-----------> Section 3.1: Consensus Halt Rollback
| > 2 minutes?     |
+------------------+
       | NO
       v
  Wait 2 minutes,
  then re-evaluate
```

---

## 3. Rollback Scenarios

### 3.1 Consensus Halt

**Trigger conditions:**
- `cometbft_consensus_height` has not increased for > 2 minutes
- Alert `ConsensusHalted` (P0) firing
- More than 1/3 of validators unreachable

**Decision criteria:**

| Condition | Action |
|-----------|--------|
| Halt caused by a known software bug | Rollback binary to last known good version |
| Halt caused by state corruption | Rollback to last snapshot + replay |
| Halt caused by validator key compromise | Halt chain, invoke security incident, rotate keys |
| Halt caused by network partition | Wait for partition to heal; do NOT rollback |
| Halt cause unknown after 10 minutes | Escalate to L2, prepare rollback to snapshot |

**Step-by-step rollback procedure:**

1. **Communicate** -- Post to #incident-response Slack channel:
   > "[CONSENSUS HALT] Chain halted at height {H}. Initiating rollback investigation. Incident commander: {name}."

2. **Gather evidence:**
   ```bash
   # On each validator:
   curl -s http://localhost:26657/status | jq '.result.sync_info'
   curl -s http://localhost:26657/dump_consensus_state | jq '.result.round_state.height_vote_set'
   journalctl -u aethelred -n 500 --no-pager > /tmp/consensus-halt-logs.txt
   ```

3. **Identify root cause** using the decision criteria table above.

4. **If binary rollback is required:**
   ```bash
   # Stop the node
   sudo systemctl stop aethelred

   # Switch to previous binary
   sudo cp /opt/aethelred/bin/aethelredd.previous /opt/aethelred/bin/aethelredd

   # Verify binary version
   /opt/aethelred/bin/aethelredd version

   # Restart
   sudo systemctl start aethelred
   ```

5. **If state rollback is required:**
   ```bash
   # Stop the node
   sudo systemctl stop aethelred

   # Backup current state
   cp -r ~/.aethelred/data ~/.aethelred/data.corrupted.$(date +%s)

   # Restore from snapshot
   aethelredd rollback             # Rolls back one block
   # OR restore from snapshot:
   aethelredd snapshots restore <snapshot_height>

   # Restart
   sudo systemctl start aethelred
   ```

6. **Verify recovery:**
   ```bash
   # Wait for blocks
   watch -n 2 'curl -s http://localhost:26657/status | jq .result.sync_info.latest_block_height'
   ```

7. **Post-incident:** File incident report within 24 hours.

---

### 3.2 Bridge Pause

**Trigger conditions:**
- Alert `BridgeRateLimitExceeded` (P1) firing
- Suspicious large withdrawals detected
- Bridge reorg event detected
- Bridge relayer key suspected compromised

**Decision criteria:**

| Condition | Action |
|-----------|--------|
| Rate limit exceeded but transactions are legitimate | Increase rate limit via governance proposal |
| Suspicious withdrawal pattern | Pause bridge immediately |
| Reorg detected | Pause bridge, wait for finality, resume |
| Relayer key compromise suspected | Pause bridge, rotate keys, audit pending txns |

**Step-by-step bridge pause procedure:**

1. **Communicate:**
   > "[BRIDGE PAUSE] Initiating emergency bridge pause. Reason: {reason}. IC: {name}."

2. **Execute emergency pause:**
   ```bash
   # Via governance multisig (preferred):
   cast send $CIRCUIT_BREAKER_ADDR "triggerEmergencyPause()" \
     --private-key $GUARDIAN_KEY --rpc-url $ETH_RPC

   # Verify pause state:
   cast call $BRIDGE_ADDR "paused()" --rpc-url $ETH_RPC
   # Expected: true
   ```

3. **Verify deposits are blocked:**
   ```bash
   # Attempt a test deposit (should revert):
   cast send $BRIDGE_ADDR "deposit(uint256)" 1 \
     --private-key $TEST_KEY --rpc-url $ETH_RPC 2>&1 | grep -i "paused"
   ```

4. **Investigate root cause** using bridge relayer logs and on-chain event history.

5. **Resume bridge** (only after root cause is resolved):
   ```bash
   cast send $CIRCUIT_BREAKER_ADDR "unpause()" \
     --private-key $GUARDIAN_KEY --rpc-url $ETH_RPC

   # Verify:
   cast call $BRIDGE_ADDR "paused()" --rpc-url $ETH_RPC
   # Expected: false
   ```

6. **Post-incident:** Verify all pending deposits/withdrawals process correctly.

---

### 3.3 Data Corruption

**Trigger conditions:**
- App hash mismatch across validators
- Database integrity check failures
- Unexpected panic/crash loops on restart

**Decision criteria:**

| Condition | Action |
|-----------|--------|
| Single validator corrupted | Restore from peer snapshot, do NOT rollback chain |
| Multiple validators same corruption | Likely software bug; rollback to common safe height |
| Corruption in bridge state | Pause bridge + restore from verified state |

**Step-by-step procedure:**

1. **Communicate:**
   > "[DATA CORRUPTION] App hash mismatch detected at height {H}. Investigating scope."

2. **Determine scope:**
   ```bash
   # Compare app hashes across validators
   for port in 26657 26757 26857 26957; do
     echo "Port ${port}: $(curl -s http://localhost:${port}/status | jq -r '.result.sync_info.latest_block_height + " " + .result.sync_info.latest_app_hash')"
   done
   ```

3. **For single-validator corruption:**
   ```bash
   sudo systemctl stop aethelred
   rm -rf ~/.aethelred/data
   # State sync from peers:
   aethelredd tendermint unsafe-reset-all
   # Configure state sync in config.toml, then restart
   sudo systemctl start aethelred
   ```

4. **For chain-wide corruption:**
   - Coordinate with all validators on Discord/Slack
   - Identify last known good height
   - All validators rollback to that height:
     ```bash
     aethelredd rollback --hard
     ```
   - Restart all validators simultaneously

---

## 4. Non-Halt Issues (Chain Still Producing Blocks)

```
Chain is producing blocks but issue detected
       |
       v
+----------------------+
| Is it a performance  |     YES
| degradation?         |-----------> Monitor; scale infra; no rollback needed
+----------------------+
       | NO
       v
+----------------------+
| Is it a bridge       |     YES
| issue?               |-----------> Section 3.2: Bridge Pause
+----------------------+
       | NO
       v
+----------------------+
| Is it a governance   |     YES
| parameter issue?     |-----------> Submit governance proposal to fix; no rollback
+----------------------+
       | NO
       v
  Log incident, monitor,
  escalate if worsening
```

---

## 5. Communication Templates

### 5.1 Initial Incident Notification

```
[INCIDENT - {SEVERITY}] {TITLE}

Status: Investigating
Time: {TIMESTAMP} UTC
Impact: {DESCRIPTION}
Incident Commander: {NAME}

Next update in 15 minutes.
```

### 5.2 Rollback Initiated

```
[INCIDENT UPDATE] Rollback in progress

Status: Rollback initiated
Rollback type: {binary|state|bridge-pause}
Target state: {DESCRIPTION}
ETA to recovery: {ESTIMATE}
Affected services: {LIST}

Next update in 10 minutes.
```

### 5.3 Recovery Confirmed

```
[INCIDENT RESOLVED] {TITLE}

Status: Resolved
Duration: {DURATION}
Root cause: {BRIEF DESCRIPTION}
Rollback performed: {YES/NO - details}
Post-incident review scheduled: {DATE}

Full incident report will be filed within 24 hours.
```

### 5.4 External Communication (Status Page / Twitter)

```
We are aware of an issue affecting {SERVICE}. Our team is actively
investigating. We will provide updates every 30 minutes.

Current status: {STATUS}
Estimated resolution: {ETA}
```

---

## 6. Escalation Matrix

| Severity | Response Time | Escalation Path |
|----------|---------------|-----------------|
| P0 Critical | Immediate | On-call SRE -> Engineering Lead -> CTO |
| P1 High | < 15 min | On-call SRE -> Engineering Lead |
| P2 Medium | < 1 hour | On-call SRE |
| P3 Low | Next business day | Ticket in backlog |

---

## 7. Related Documents

- [OPS_RUNBOOK.md](OPS_RUNBOOK.md) -- Day-2 operational procedures
- [SECURITY_RUNBOOKS.md](../security/SECURITY_RUNBOOKS.md) -- Security incident response
- [MONITORING.md](../security/MONITORING.md) -- Alerting thresholds and SLOs
- [hsm-requirements.md](../security/hsm-requirements.md) -- HSM key management
