# Aethelred Tokenomics

**Document Classification:** Confidential — For ADGM DLT Foundation Registration
**Version:** 2.0
**Date:** March 11, 2026
**Prepared by:** Aethelred Foundation
**Status:** Final

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Token Overview](#2-token-overview)
3. [Supply Architecture](#3-supply-architecture)
4. [Token Allocation & Distribution](#4-token-allocation--distribution)
5. [Vesting Schedules](#5-vesting-schedules)
6. [Circulating Supply Projection](#6-circulating-supply-projection)
7. [Fundraising Breakdown](#7-fundraising-breakdown)
8. [TGE Metrics](#8-tge-metrics)
9. [Airdrop Program (Seals)](#9-airdrop-program-seals)
10. [Market Maker Strategy](#10-market-maker-strategy)
11. [Fee Market Design](#11-fee-market-design)
12. [Fee Distribution](#12-fee-distribution)
13. [Staking Economics](#13-staking-economics)
14. [Slashing & Economic Security](#14-slashing--economic-security)
15. [Deflationary Mechanisms](#15-deflationary-mechanisms)
16. [Treasury & Operational Runway](#16-treasury--operational-runway)
17. [Governance Economics](#17-governance-economics)
18. [Bridge Economics](#18-bridge-economics)
19. [Institutional Stablecoin Infrastructure](#19-institutional-stablecoin-infrastructure)
20. [AI Compute Market Economics](#20-ai-compute-market-economics)
21. [Validator Economics](#21-validator-economics)
22. [Economic Security Analysis](#22-economic-security-analysis)
23. [Post-Quantum Cryptographic Considerations](#23-post-quantum-cryptographic-considerations)
24. [Formal Verification & Audit](#24-formal-verification--audit)
25. [Mainnet Launch Economics](#25-mainnet-launch-economics)
26. [Key Dates & Milestones](#26-key-dates--milestones)
27. [Competitive Benchmarks](#27-competitive-benchmarks)
28. [Risk Factors & Mitigations](#28-risk-factors--mitigations)
29. [Long-Term Economic Sustainability](#29-long-term-economic-sustainability)
30. [Regulatory Compliance Design](#30-regulatory-compliance-design)
31. [Appendix A — Parameter Reference](#appendix-a--parameter-reference)
32. [Appendix B — Mathematical Proofs](#appendix-b--mathematical-proofs)

---

## 1. Executive Summary

Aethelred is a sovereign Layer 1 blockchain purpose-built for verifiable artificial intelligence computation. The AETHEL token serves as the native cryptoeconomic primitive powering the network's Proof-of-Useful-Work (PoUW) consensus, where validators earn rewards by performing and verifying real AI inference workloads — not arbitrary hash puzzles.

The tokenomics are designed around five core principles:

1. **Fixed Supply, No Inflation** — A hard-capped supply of 10,000,000,000 AETHEL with zero inflation. All tokens are minted at genesis and distributed through predetermined vesting schedules, providing absolute supply predictability.

2. **Deflationary Pressure** — A multi-layered burn mechanism (base fee burn, congestion-squared burn, adaptive quadratic burn) creates permanent token destruction that increases with network utilisation, making AETHEL progressively scarcer over time.

3. **Conservative Float** — Only 6.3% of total supply enters circulation at TGE, minimising initial sell pressure while providing sufficient liquidity for ecosystem bootstrapping and market-making operations.

4. **Economic Security** — A four-tier slashing framework, reputation-scaled rewards, and anti-concentration limits ensure that the cost of attacking the network always exceeds the potential gain.

5. **Institutional Grade** — Compliance-first design with OFAC-compatible blacklisting, auditable compliance burns, timelocked governance, circuit breakers, and multi-signature requirements at every critical juncture.

**Key Figures:**

| Metric | Value |
|--------|-------|
| Total Supply (Fixed) | 10,000,000,000 AETHEL |
| Supply Model | Fixed — No inflation |
| TGE Circulating Supply | 630,000,000 AETHEL (6.3%) |
| TGE Price Target | $0.10 / AETHEL |
| TGE Fully Diluted Valuation | $1,000,000,000 |
| TGE Market Capitalisation | $63,000,000 |
| Total Fundraise | $16,000,000 |
| Average Investor Entry | $0.0194 / AETHEL |
| Fee Burn Rate | 20% of all transaction fees |
| BFT Security Threshold | > 2/3 (67%) |
| Validator Set | Up to 100 validators |
| Minimum Stake | 100,000 AETHEL |

---

## 2. Token Overview

### 2.1 Token Identity

| Property | Value |
|----------|-------|
| Name | Aethelred |
| Ticker | AETHEL |
| Token Standard | ERC-20 (Upgradeable) with ERC-20Votes, ERC-20Permit |
| Solidity Decimals | 18 |
| Cosmos Denomination | uaethel (micro-AETHEL, 6 decimals) |
| EVM Denomination | wei (18 decimals) |
| Cross-Layer Scale Factor | 1 uaethel = 10^12 wei |
| Chain ID (Mainnet) | aethelred-1 (Cosmos) / 8821 (EVM) |
| Chain ID (Testnet) | aethelred-testnet-1 / 88210 (EVM) |

### 2.2 Multi-Layer Denomination

Aethelred operates a unified token across its Cosmos SDK consensus layer and its EVM-compatible execution environment. The denomination bridge is a deterministic, lossless conversion:

```
1 AETHEL   = 1,000,000 uaethel (Cosmos layer, 6 decimals)
1 AETHEL   = 1,000,000,000,000,000,000 wei (EVM layer, 18 decimals)
1 uaethel = 1,000,000,000,000 wei (scale factor: 10^12)
```

This dual-denomination design allows the Cosmos consensus layer to operate with efficient 64-bit integer arithmetic while the EVM layer maintains full Ethereum compatibility.

### 2.3 Token Capabilities

The AETHEL token contract implements:

- **ERC-20Votes** — On-chain governance voting power delegation and checkpointing.
- **ERC-20Permit** (EIP-2612) — Gasless approvals via off-chain signatures.
- **ERC-20Burnable** — Holder-initiated token burning.
- **Pausable** — Emergency circuit breaker for all transfers.
- **UUPS Upgradeable** — Timelocked, multi-signature-controlled upgrade path.
- **Compliance Module** — OFAC/sanctions blacklisting with auditable compliance burns.
- **Bridge Integration** — Authorised bridge contracts can mint/burn within the supply cap.
- **Transfer Restrictions** — Pre-TGE transfer lock with whitelist exemptions.

### 2.4 Access Control

All administrative operations require multi-signature authorisation on production chains. Six distinct roles enforce separation of duties:

| Role | Capability |
|------|-----------|
| Admin | Bridge authorisation, transfer restriction management |
| Minter | Token minting (supply-cap enforced) |
| Pauser | Emergency pause/unpause |
| Compliance | Blacklist/whitelist management |
| Compliance Burn | Regulatory token seizure with audit trail |
| Upgrader | Contract upgrade authorisation (27-day timelock) |

---

## 3. Supply Architecture

### 3.1 Hard Cap — Fixed Supply

The AETHEL token has a **hard-capped, fixed supply of 10,000,000,000 tokens** (10 billion). There is **no inflation**. All tokens are minted at genesis and distributed according to predetermined vesting schedules. The supply cap is enforced at the smart contract level via the `TOTAL_SUPPLY_CAP` constant and is immutable — no upgrade, governance vote, or administrative action can increase it.

Every mint path — direct minting, bridge minting, and vesting distribution — enforces a pre-mint check:

```
require(totalSupply() + amount <= TOTAL_SUPPLY_CAP)
```

### 3.2 Genesis Minting

The full 10 billion AETHEL is minted at genesis and allocated across nine categories with distinct vesting schedules. No additional tokens are ever created. The PoUW Rewards pool (3 billion AETHEL) is distributed linearly over 10 years to validators performing useful AI computation, providing economic security incentives without inflationary minting.

### 3.3 Circulating Supply at TGE

At Token Generation Event (December 7-10, 2026), **6.3% of total supply** enters circulation:

| Source | TGE Unlock % | TGE Tokens |
|--------|-------------|-----------|
| Public Sales (20% of 750M) | 20.0% | 150,000,000 |
| Treasury & Market Makers (25% of 600M) | 25.0% | 150,000,000 |
| Airdrop / Seals (25% of 700M) | 25.0% | 175,000,000 |
| Insurance Fund (10% of 500M) | 10.0% | 50,000,000 |
| Ecosystem & Grants (2% of 1.5B) | 2.0% | 30,000,000 |
| **Total Circulating at TGE** | **6.3%** | **630,000,000 AETHEL** |

This 6.3% TGE float balances market liquidity needs (including market maker inventory and exchange listings) with sell-pressure containment. At the target TGE price of $0.10/AETHEL, the circulating market capitalisation is $63 million against a fully diluted valuation of $1 billion.

---

## 4. Token Allocation & Distribution

### 4.1 Allocation Summary

| Category | Allocation | Tokens | TGE Unlock | Purpose |
|----------|-----------|--------|-----------|---------|
| PoUW Rewards | 30.0% | 3,000,000,000 | 0% | Validator and compute provider rewards (10-year program) |
| Core Contributors | 20.0% | 2,000,000,000 | 0% | Founding team, early engineers, and key contributors |
| Ecosystem & Grants | 15.0% | 1,500,000,000 | 2% | Developer grants, ecosystem growth, partnerships |
| Treasury & Market Makers | 6.0% | 600,000,000 | 25% | Operational runway + market maker inventory loans |
| Public Sales | 7.5% | 750,000,000 | 20% | Echo community round + exchange listing sales |
| Airdrop (Seals) | 7.0% | 700,000,000 | 25% | Community incentives via Seals points program |
| Strategic / Seed | 5.5% | 550,000,000 | 0% | Seed and strategic investment rounds |
| Insurance Fund | 5.0% | 500,000,000 | 10% | Slashing appeals and hack indemnification |
| Contingency Reserve | 4.0% | 400,000,000 | 0% | Unknown unknowns; strategic pivots |
| **Total** | **100.0%** | **10,000,000,000** | **6.3%** | |

### 4.2 Design Rationale

**PoUW Rewards (30%):** The largest single allocation ensures a full decade of meaningful rewards for validators performing useful AI work. Distributed linearly at 25,000,000 AETHEL per month with no cliff, ensuring immediate participation incentives from network launch. This pool is the engine that bootstraps network effects — the more compute is rewarded, the more validators join, the more AI workloads the network can serve.

**Core Contributors (20%):** Aligned with industry best practices (Sui 20%, Aptos 20%, Celestia 20%, Arbitrum ~27%). A 6-month cliff followed by 42-month linear vesting (48 months total) balances team retention with operational needs. Schedules are revocable if contributors depart before vesting completion.

**Ecosystem & Grants (15%):** Fuels developer adoption through grants, hackathons, and partnerships. The conservative 2% TGE unlock provides initial capital for ecosystem bootstrapping while the 6-month cliff and 48-month linear vesting ensure sustained, metered investment over 4.5 years.

**Treasury & Market Makers (6%):** Combined operational treasury and market maker inventory. The 25% TGE unlock (150M AETHEL) provides immediate capital for market maker loans (Wintermute, GSR) and operational expenses. Market maker tokens are loaned, not sold — they are returnable per agreement, ensuring they serve as price support rather than sell pressure. Remaining 75% vests linearly over 36 months.

**Public Sales (7.5%):** Split between the Echo community round (400M tokens at $0.015) and the exchange listing round (175M tokens at $0.03). The 20% TGE unlock provides day-one market liquidity. The remaining 80% vests linearly over 18 months — the shortest vesting of any category, reflecting the community's need for accessible tokens.

**Airdrop / Seals (7.0%):** A tiered community incentive program distributing 700M AETHEL based on a points system running from March 2026 through the November 2026 snapshot. The 25% TGE unlock (175M AETHEL) provides immediate rewards to early participants while 75% vests over 12 months, maintaining ongoing engagement incentives.

**Strategic / Seed (5.5%):** Conservative allocation across Seed ($0.01/AETHEL) and Strategic ($0.025/AETHEL) rounds. Zero TGE unlock with a 12-month cliff followed by 24-month linear vesting (36 months total) ensures investor alignment with long-term protocol success.

**Insurance Fund (5.0%):** A dedicated on-chain insurance fund governed by a 3-of-5 multi-signature (2 team + 2 advisors + 1 auditor). Maximum 10M AETHEL per incident. The 10% TGE unlock ensures the fund is operational from day one. Linear vesting over 30 months.

**Contingency Reserve (4.0%):** Reserved for unforeseen circumstances — emergency funding, strategic pivots, or opportunities that cannot be anticipated at genesis. Zero TGE unlock with 12-month cliff. Release requires team + advisor majority vote with a 30-day timelock.

---

## 5. Vesting Schedules

### 5.1 Schedule Parameters

All vesting schedules are enforced on-chain through the `AethelredVesting` smart contract. Vesting is linear after cliff expiry, with no acceleration clauses.

| Category | TGE Unlock | Cliff | Cliff Unlock | Linear Period | Total Duration | Monthly Unlock | End Date | Revocable |
|----------|-----------|-------|-------------|--------------|----------------|---------------|----------|-----------|
| PoUW Rewards | 0% | None | — | 120 months | 120 months | 25,000,000 | Dec 2036 | No |
| Core Contributors | 0% | 6 months | — | 42 months | 48 months | 41,666,667 | Mar 2030 | Yes |
| Ecosystem & Grants | 2% | 6 months | — | 48 months | 54 months | 23,750,000 | Mar 2031 | No |
| Treasury & MM | 25% | None | — | 36 months | 36 months | 12,500,000 | Dec 2029 | No |
| Public Sales | 20% | None | — | 18 months | 18 months | 29,166,667 | Jun 2028 | No |
| Airdrop (Seals) | 25% | None | — | 12 months | 12 months | 43,750,000 | Dec 2027 | No |
| Strategic / Seed | 0% | 12 months | — | 24 months | 36 months | 22,916,667 | Dec 2028 | No |
| Insurance Fund | 10% | None | — | 30 months | 30 months | 12,500,000 | Jun 2029 | No |
| Contingency Reserve | 0% | 12 months | TBD | TBD | TBD | TBD | TBD | Special |

### 5.2 Core Contributors Detailed Vesting

The Core Contributors vesting follows a cliff-then-linear schedule over 48 months:

| Period | Month | Cumulative Unlock | Tokens Unlocked | Remaining |
|--------|-------|------------------|----------------|----------|
| Cliff | 1–6 | 0% | 0 | 2,000,000,000 |
| Cliff End | 6 | 0% | 0 | 2,000,000,000 |
| Month 12 | 12 | 12.50% | 250,000,000 | 1,750,000,000 |
| Month 18 | 18 | 25.00% | 500,000,000 | 1,500,000,000 |
| Month 24 | 24 | 37.50% | 750,000,000 | 1,250,000,000 |
| Month 30 | 30 | 50.00% | 1,000,000,000 | 1,000,000,000 |
| Month 36 | 36 | 62.50% | 1,250,000,000 | 750,000,000 |
| Month 42 | 42 | 75.00% | 1,500,000,000 | 500,000,000 |
| Month 48 | 48 | 87.50% | 1,750,000,000 | 250,000,000 |

### 5.3 Vesting Formula

For any block height `h`, the vested amount for a schedule is computed as:

```
TGE_amount     = total_allocation * TGE_unlock_bps / 10,000
Cliff_amount   = total_allocation * cliff_unlock_bps / 10,000
Remaining      = total_allocation - TGE_amount - Cliff_amount
Linear_period  = vesting_blocks - cliff_blocks

if h < cliff_blocks:
    vested = TGE_amount
elif h >= vesting_blocks:
    vested = total_allocation
else:
    linear_elapsed = h - cliff_blocks
    linear_vested  = Remaining * linear_elapsed / Linear_period
    vested = TGE_amount + Cliff_amount + linear_vested
```

**Safety Properties (formally verified):**
- **Monotonicity:** `vested(h) <= vested(h + 1)` for all `h` — vested amounts never decrease.
- **Boundedness:** `vested(h) <= total_allocation` for all `h`.
- **Solvency:** Contract balance >= sum of all unvested amounts at all times.

### 5.4 Vesting Types

The contract supports five vesting modalities:

1. **Linear** — Continuous linear unlock over the duration.
2. **Cliff-Linear** — Cliff period followed by linear vesting.
3. **Immediate** — 100% at TGE (used for TGE unlock portions).
4. **DAO-Controlled** — Released via on-chain governance proposals.
5. **Milestone-Based** — Released upon achievement of predefined milestones with dual-attestation (requires both Vesting Admin and Milestone Attestor roles).

---

## 6. Circulating Supply Projection

### 6.1 Monthly Projection

| Month | Cumulative Unlock | % of Supply | Key Events |
|-------|------------------|-------------|------------|
| 0 (TGE) | 630,000,000 | 6.3% | TGE unlocks: Public Sales, Treasury/MM, Airdrop, Insurance, Ecosystem |
| 6 | ~1,130,000,000 | 11.3% | Core Contributors cliff ends (linear begins), Ecosystem cliff, linear vesting |
| 12 | ~2,250,000,000 | 22.5% | Strategic/Seed cliff, Contingency cliff, Airdrop fully vested |
| 18 | ~3,050,000,000 | 30.5% | Public Sales fully vested, ongoing linear unlocks |
| 24 | ~4,050,000,000 | 40.5% | Strategic/Seed fully vested |
| 30 | ~4,800,000,000 | 48.0% | Insurance fully vested |
| 36 | ~5,600,000,000 | 56.0% | Treasury & MM fully vested, Strategic/Seed fully vested |
| 48 | ~7,100,000,000 | 71.0% | Core Contributors fully vested, significant Ecosystem unlocks |
| 54 | ~7,600,000,000 | 76.0% | Ecosystem fully vested |
| 120 | 10,000,000,000 | 100.0% | PoUW Rewards fully distributed |

### 6.2 Effective Circulating Supply

The effective circulating supply at any point is further reduced by:
- **Staked tokens** — At the 55% staking target, approximately half of circulating tokens are locked in staking contracts.
- **Burned tokens** — Cumulative burns from the deflationary mechanisms permanently reduce circulating supply.
- **Market maker loans** — 200M AETHEL loaned to market makers (125M Wintermute + 75M GSR) are returnable, not freely circulating sell-side inventory.
- **Insurance fund holdings** — Governance-locked for incident response.

---

## 7. Fundraising Breakdown

### 7.1 Round Summary

| Round | Amount Raised | Tokens Allocated | Price per Token | % of Supply | Implied FDV | Timing | Source Bucket | Status |
|-------|--------------|-----------------|----------------|-------------|-------------|--------|---------------|--------|
| Seed | $1,000,000 | 100,000,000 | $0.010 | 1.00% | $100,000,000 | Mar–Apr 2026 | Strategic/Seed | Target |
| Community (Echo) | $6,000,000 | 400,000,000 | $0.015 | 4.00% | $150,000,000 | Jun–Jul 2026 | Public Sales | Target |
| Strategic | $3,750,000 | 150,000,000 | $0.025 | 1.50% | $250,000,000 | Sep–Oct 2026 | Strategic/Seed | Target |
| Exchange (Binance) | $5,250,000 | 175,000,000 | $0.030 | 1.75% | $300,000,000 | Nov 2026 | Public Sales | Target |
| Buffer / Advisors | $0 | 75,000,000 | — | 0.75% | — | — | From buckets above | Over-allotment / bridge |
| **Total** | **$16,000,000** | **825,000,000** | **$0.0194 avg** | **8.25%** | — | — | — | |

### 7.2 Fundraising Strategy

**Seed Round ($1M at $100M FDV):** Earliest believers receive the deepest discount (10x upside to TGE at $0.10). Small raise preserves equity value and limits early dilution. 12-month cliff + 24-month linear vesting ensures alignment.

**Community / Echo Round ($6M at $150M FDV):** Conducted via Coinbase Echo or equivalent community platform to maximise decentralised distribution. The largest single round by token count (400M AETHEL) ensures broad community ownership. 20% TGE unlock provides immediate liquidity for participants.

**Strategic Round ($3.75M at $250M FDV):** Targeted at institutional and strategic investors who bring ecosystem value beyond capital — infrastructure partners, AI companies, exchange partners. 12-month cliff ensures long-term alignment.

**Exchange Round ($5.25M at $300M FDV):** Conducted with the primary exchange listing partner (Binance target, with Bybit/OKX as contingency). Combined with listing agreement to ensure day-one centralised exchange availability.

### 7.3 Use of Proceeds

| Category | Amount | % of Raise | Purpose |
|----------|--------|-----------|---------|
| Engineering | $6,400,000 | 40% | Core protocol development, VM, consensus, cryptography |
| Infrastructure | $2,400,000 | 15% | Validator infrastructure, TEE provisioning, devnet/testnet |
| Security | $2,400,000 | 15% | Audits (Trail of Bits, OtterSec), bug bounty, formal verification |
| Business Development | $1,600,000 | 10% | Exchange listings, partnerships, market making setup |
| Legal & Compliance | $1,600,000 | 10% | ADGM registration, regulatory counsel, compliance infrastructure |
| Operations | $1,600,000 | 10% | Office, administration, travel, contingency |
| **Total** | **$16,000,000** | **100%** | |

### 7.4 Investor Upside

| Metric | Value |
|--------|-------|
| Weighted Average Entry Price | $0.0194 / AETHEL |
| TGE Target Price | $0.10 / AETHEL |
| Investor Upside at TGE | **5.15x** |
| Seed Round Upside at TGE | **10.0x** |
| Echo Round Upside at TGE | **6.67x** |
| Strategic Round Upside at TGE | **4.0x** |
| Exchange Round Upside at TGE | **3.33x** |

---

## 8. TGE Metrics

### 8.1 Token Generation Event

| Metric | Value | Notes |
|--------|-------|-------|
| TGE Date | December 7–10, 2026 | At Abu Dhabi Finance Week |
| Total Supply | 10,000,000,000 AETHEL | Fixed supply; no inflation |
| TGE Circulating Supply | 630,000,000 AETHEL | 6.3% of total supply |
| TGE Price Target | $0.10 / AETHEL | Target, not guarantee |
| TGE Market Cap | $63,000,000 | Circulating supply * price |
| Fully Diluted Valuation | $1,000,000,000 | Max supply * TGE price |
| Average Investor Entry | $0.0194 / AETHEL | Weighted average across all rounds |
| Investor Upside at TGE | 5.15x | $0.10 / $0.0194 |
| Treasury Runway | 18+ months | Based on $16M raise + controlled TGE unlock |

### 8.2 Float Analysis

The 6.3% TGE float is deliberately conservative relative to comparable L1 launches:

| Metric | AETHEL (This Model) | Industry Range |
|--------|------------------|---------------|
| TGE Float | 6.3% | 5–20% |
| FDV at TGE | $1.0B | $0.3–2.0B |
| Team TGE Unlock | 0% | 0–10% |
| Investor TGE Unlock | 0% | 0–15% |
| Airdrop TGE Unlock | 25% | 10–100% |
| Market Cap / FDV | 6.3% | 5–15% |

The low Market Cap / FDV ratio creates natural price appreciation potential as the market recognises the implied valuation of the unlocked supply.

---

## 9. Airdrop Program (Seals)

### 9.1 Program Overview

The Seals airdrop program distributes **700,000,000 AETHEL** (7% of total supply) to community members based on a points-based engagement system running from March 2026 through the November 2026 snapshot.

### 9.2 Tier Structure

| Tier | Points Required | Airdrop per User (AETHEL) | Est. Users | Total Tokens | TGE Unlock (25%) | Vesting (75%) |
|------|----------------|----------------------|-----------|-------------|-----------------|--------------|
| Diamond | 10,000+ | 50,000 | 500 | 25,000,000 | 6,250,000 | 18,750,000 |
| Gold | 5,000–9,999 | 20,000 | 2,000 | 40,000,000 | 10,000,000 | 30,000,000 |
| Silver | 1,000–4,999 | 5,000 | 10,000 | 50,000,000 | 12,500,000 | 37,500,000 |
| Bronze | 100–999 | 500 | 50,000 | 25,000,000 | 6,250,000 | 18,750,000 |
| **Initial Subtotal** | — | — | **62,500** | **140,000,000** | **35,000,000** | **105,000,000** |

### 9.3 Additional Allocations

| Programme | Per-User Allocation (AETHEL) | Total Reserve | TGE Unlock (25%) | Vesting (75%) |
|-----------|--------------------------|--------------|-----------------|--------------|
| Ongoing Incentives | Variable | 210,000,000 | 52,500,000 | 157,500,000 |
| Testnet Bonus | 5,000 | (from reserve) | 12,500,000 | 37,500,000 |
| Echo Early Registration | 5,000 | (from reserve) | 12,500,000 | 37,500,000 |
| **Total Airdrop** | — | **700,000,000** | **175,000,000** | **525,000,000** |

### 9.4 Program Timeline

| Date | Milestone |
|------|-----------|
| March 2026 | Program launch — points accrual begins via Discord, X, Telegram |
| May 1, 2026 | Testnet launch — points for validators and bug bounties |
| November 2026 | Snapshot — final Seals points tally for TGE distribution |
| December 7–10, 2026 | Distribution — at TGE during Abu Dhabi Finance Week |

### 9.5 Points Accrual Activities

- Social engagement (Discord, X, Telegram participation)
- Testnet validation (running validators, reporting bugs)
- Content creation (tutorials, translations, educational content)
- Community moderation and governance participation
- Bug bounty submissions
- Developer activity (dApp deployment, SDK contributions)

---

## 10. Market Maker Strategy

### 10.1 Market Making Partners

| Partner | Allocation | Token Amount | TGE Available | Type | Terms |
|---------|-----------|-------------|--------------|------|-------|
| Wintermute | Loan | 125,000,000 | 125,000,000 | Primary Market Maker | 3-month loan; returnable + fee |
| GSR | Loan | 75,000,000 | 75,000,000 | Secondary Market Maker | 3-month loan; returnable + fee |
| Exchange Listings | Listing | 175,000,000 | 43,750,000 | Exchange Liquidity | Per listing agreement |
| **Total MM Ammunition** | — | **375,000,000** | **243,750,000** | — | ~$37.5M at $1B FDV |

### 10.2 Design Rationale

- **Loan structure, not sale:** Market maker tokens are loaned with a return obligation plus fee. This ensures MM inventory supports price discovery and liquidity rather than creating sell pressure.
- **Dual MM approach:** Wintermute (primary) and GSR (secondary) provide redundancy, competitive pricing, and coverage across multiple exchanges.
- **$37.5M total ammunition** at target FDV provides substantial firepower for price stability during the critical TGE and early trading period.
- **3-month renewable loans** allow the Foundation to reassess market conditions and MM performance quarterly.

### 10.3 Exchange Strategy

**Primary:** Binance listing at TGE (November 2026 exchange round).
**Contingency:** Bybit or OKX if Binance timeline shifts.
**DEX:** Uniswap V3 or equivalent DEX listing as backup and for DeFi accessibility.

---

## 11. Fee Market Design

### 11.1 Base Fee

Every AI inference job submitted to Aethelred incurs a base fee denominated in AETHEL. The base fee is the minimum cost of on-chain computation and verification.

| Parameter | Value |
|-----------|-------|
| Base Fee | 0.001 AETHEL (1,000 uaethel) |
| Maximum Multiplier | 5.0x |
| Congestion Threshold | 70% block utilisation |
| Adjustment Rate | 1% per block |
| Backlog Window | 10 blocks |

### 11.2 Dynamic Fee Adjustment

Aethelred implements an EIP-1559-inspired dynamic fee market with congestion-responsive pricing:

```
capacity = max_jobs_per_block * backlog_window

utilisation_bps = pending_jobs * 10,000 / capacity

if utilisation_bps <= congestion_threshold:
    effective_fee = base_fee
else:
    excess = utilisation_bps - congestion_threshold
    range  = 10,000 - congestion_threshold
    multiplier_bps = 10,000 + (max_multiplier_bps - 10,000) * excess / range
    effective_fee = base_fee * multiplier_bps / 10,000
```

The base fee adjusts by a maximum of +/- 12.5% per block based on whether block utilisation exceeds or falls below the 50% target, providing smooth price discovery.

### 11.3 Priority Tiers

Users can select a priority tier to expedite job execution:

| Tier | Fee Multiplier | Use Case |
|------|---------------|----------|
| Standard | 1.0x | Batch inference, non-time-sensitive |
| Fast | 2.0x | Interactive applications, moderate latency |
| Urgent | 5.0x | Real-time inference, financial applications |

### 11.4 Hardware Fee Multipliers

Job fees scale with the security and cost profile of the hardware executing the computation:

| Hardware Environment | Fee Multiplier |
|---------------------|---------------|
| Generic CPU/GPU | 1.0x |
| Intel SGX / AMD SEV | 1.2x |
| AWS Nitro Enclave | 1.5x |
| NVIDIA H100 Confidential | 2.0x |

### 11.5 Jurisdiction Fee Multipliers

Regulatory compliance overhead in certain jurisdictions is reflected in fee multipliers:

| Jurisdiction | Fee Multiplier |
|-------------|---------------|
| Global (default) | 1.0x |
| European Union | 1.1x |
| United States | 1.1x |
| Singapore | 1.2x |
| UAE | 1.3x |
| China | 1.4x |
| Saudi Arabia | 1.5x |

### 11.6 Composite Fee Calculation

The total fee for a job is:

```
Total Fee = Base Fee * Dynamic Multiplier * Priority Multiplier
            * Hardware Multiplier * Jurisdiction Multiplier
```

---

## 12. Fee Distribution

### 12.1 Distribution Split

All fees collected from AI inference jobs are distributed across four protocol buckets. The split is enforced on-chain and must sum to exactly 10,000 BPS (100%):

| Bucket | Share | Purpose |
|--------|-------|---------|
| Validator Rewards | 40% (4,000 BPS) | Direct compensation for validators performing and verifying compute |
| Treasury | 30% (3,000 BPS) | Protocol development, grants, and operational funding |
| Burn | 20% (2,000 BPS) | Permanent token destruction for deflationary pressure |
| Insurance Fund | 10% (1,000 BPS) | Economic stability reserve for slashing events and black swan scenarios |

### 12.2 Validator Reward Distribution

Validator rewards are distributed equally among all bonded, non-jailed validators, then scaled by reputation:

```
per_validator_base = validator_total / validator_count

scale_factor    = 50 + (reputation_score / 2)
scaled_reward   = per_validator_base * scale_factor / 100
```

| Reputation Score | Reward Multiplier |
|-----------------|-------------------|
| 0 (minimum) | 50% of base |
| 50 (default) | 75% of base |
| 100 (maximum) | 100% of base |

This creates a meritocratic incentive structure where validators who consistently deliver correct, timely results earn proportionally more.

### 12.3 Dust Handling

Any remainder from integer division in the distribution calculation is added to the treasury, ensuring no tokens are lost to rounding.

---

## 13. Staking Economics

### 13.1 Staking Parameters

| Parameter | Value | Governance Bounds |
|-----------|-------|-------------------|
| Minimum Validator Stake | 100,000 AETHEL | >= 1 AETHEL |
| Minimum Compute Node Stake | 10,000 AETHEL | — |
| Minimum Delegator Stake | 100 AETHEL | — |
| Maximum Validators | 100 | [5, 500] |
| Minimum Commission | 5% (500 BPS) | [1%, 50%] |
| Maximum Commission | 20% (2,000 BPS) | <= 50% |
| Unbonding Period (Validator) | 21 days (302,400 blocks) | >= 7 days |
| Unbonding Period (Compute) | 7 days | — |
| Unbonding Period (Delegator) | 14 days | — |
| Redelegation Cooldown | 7 days (100,800 blocks) | — |
| Staking Target | 55% of supply | [20%, 90%] |

### 13.2 Validator Concentration Limits

To prevent centralisation, no single validator may control more than **33% (3,300 BPS)** of total staked supply. This anti-concentration cap is enforced at the staking transaction level.

A progressive penalty multiplier of **150% (15,000 BPS)** applies to validators approaching the concentration cap, making over-concentration economically unattractive before the hard limit is reached.

### 13.3 Reputation System

Every validator maintains an on-chain reputation score from 0 to 100, initialised at 50:

| Event | Score Change |
|-------|-------------|
| Successful job completion | +1 (cap at 100) |
| Failed job | -5 (floor at 0) |
| Slashing event | Score halved |

Reputation directly affects economic outcomes through the reward scaling formula (Section 12.2) and influences job assignment priority in the scheduler.

### 13.4 Compute Bonus

Validators that operate Trusted Execution Environment (TEE) hardware receive a **1.5x compute bonus multiplier** on their rewards, reflecting the additional security guarantees and hardware investment.

### 13.5 Staking Yield

With a fixed supply and PoUW rewards distributed at 25M AETHEL/month (300M/year), staking yields depend on the staking ratio:

| Staking Ratio | Staked Supply | Approximate APY |
|---------------|--------------|----------------|
| 30% | 3.0B | ~10.0% |
| 40% | 4.0B | ~7.5% |
| 55% (target) | 5.5B | ~5.5% |
| 70% | 7.0B | ~4.3% |
| 80% | 8.0B | ~3.8% |

When staking falls below target, yields rise to attract more stake. When staking exceeds target, yields compress to encourage capital deployment elsewhere in the ecosystem.

---

## 14. Slashing & Economic Security

### 14.1 Slashing Tiers

Aethelred implements a four-tier slashing framework calibrated to the severity and intentionality of the offense:

| Tier | Offense | Slash Rate | Jail Duration | Permanent Ban |
|------|---------|-----------|---------------|---------------|
| Minor Fault | Brief downtime, missed votes | 0.5% | 1 day | No |
| Major Fault | Extended downtime, repeated failures | 10.0% | 7 days | No |
| Fraud | Submitting false computation results | 50.0% | 1 year | Yes |
| Critical Byzantine | Coordinated attack, double-signing | 100.0% | Permanent | Yes |

### 14.2 Specific Slashing Conditions

| Condition | Slash Rate | Detection |
|-----------|-----------|-----------|
| Double-signing | 50% | Equivocation evidence |
| Downtime (< 50% signed in 10,000 blocks) | 1% | Liveness tracker |
| Invalid computation result | 10% | Verification mismatch |
| Fake TEE attestation | 100% | Attestation verification |
| Collusion (coordinated fraud) | 100% | On-chain analysis |

### 14.3 Deterrence Analysis

The slashing framework is designed so that the cost of misbehaviour always exceeds the potential gain:

```
Deterrence Ratio = Slash Amount / Potential Gain

For all attack vectors: Deterrence Ratio > 1 (enforced by parameter validation)
```

For a validator with the minimum stake of 100,000 AETHEL:
- **Fraud attempt:** Slashes 50,000 AETHEL — the maximum gain from a single fraudulent inference is orders of magnitude less.
- **Double-sign:** Slashes 50,000 AETHEL — the economic gain from double-signing is bounded by a single block's rewards.
- **Critical Byzantine:** Slashes 100,000 AETHEL (entire stake) — total destruction of economic position.

### 14.4 Insurance Fund

Slashing proceeds are directed to the Insurance Fund. The fund operates under a **3-of-5 multi-signature** (2 team members + 2 advisors + 1 external auditor):

| Parameter | Value |
|-----------|-------|
| Maximum per Incident | 10,000,000 AETHEL |
| Multi-sig Requirement | 3-of-5 |
| Timelock (> 10M tokens) | 7 days |
| Reporting | Quarterly transparency reports |

---

## 15. Deflationary Mechanisms

Aethelred employs three complementary burn mechanisms that create increasing deflationary pressure as network utilisation grows. With a fixed supply (no inflation), every burned token permanently reduces the total circulating supply.

### 15.1 Base Fee Burn

**20% of all transaction fees are permanently burned.** This is the primary deflationary mechanism and operates at a constant rate regardless of network conditions.

```
burn_amount = total_fees * 2,000 / 10,000
```

### 15.2 Congestion-Squared Burn

When block utilisation exceeds 50%, an additional quadratic burn activates:

```
Congestion = clamp((block_utilisation - 0.5) / 0.5, 0, 1)
Burn_Rate  = Base_Fee * (1 + Congestion^2)
```

At full utilisation, this doubles the effective burn rate. The quadratic curve ensures the mechanism activates gently near the threshold and accelerates aggressively at high congestion.

### 15.3 Adaptive Quadratic Burn

A protocol-level adaptive burn operates between configurable bounds:

| Parameter | Value |
|-----------|-------|
| Minimum Burn Rate | 5% (500 BPS) |
| Maximum Burn Rate | 20% (2,000 BPS) |
| Curve Type | Quadratic |

### 15.4 Net Deflationary by Design

Since AETHEL has a **fixed supply with zero inflation**, every burn is a permanent, irreversible reduction in total supply. The token is structurally deflationary from day one — the only question is the rate of deflation, which scales with network utilisation.

Over time, the combination of:
- 20% base fee burn on all transactions
- Congestion-squared burn during high utilisation
- Adaptive quadratic burn
- Compliance burns (regulatory seizures)
- Voluntary holder burns (ERC-20Burnable)

creates a monotonically decreasing supply curve, making AETHEL progressively scarcer as the network becomes more useful.

---

## 16. Treasury & Operational Runway

### 16.1 Treasury Funding Sources

| Source | Mechanism |
|--------|----------|
| TGE Unlock | 25% of Treasury & MM allocation (150,000,000 AETHEL) |
| Fee Revenue | 30% of all job fees directed to treasury |
| Monthly Vesting | 12,500,000 AETHEL/month linear over 36 months |

### 16.2 Treasury Governance

| Parameter | Value |
|-----------|-------|
| Control | Team-controlled (CEO + CFO + CTO) |
| Timelock (> $500K) | 14 days |
| Reporting | Regular board reporting |
| Runway Target | 18+ months based on $16M raise |

### 16.3 Grant Parameters

| Parameter | Value |
|-----------|-------|
| Maximum Single Grant | 10,000 AETHEL |
| Grant Voting Period | 7 days (100,800 blocks) |
| Grant Quorum | 33% (3,300 BPS) |

### 16.4 Ecosystem Fund Governance

The Ecosystem & Grants allocation (1.5 billion AETHEL) operates under strict controls:
- **Multi-signature requirement:** 4-of-7 signers
- **Timelock:** 48 hours on all disbursements
- **Monthly unlock cap:** Maximum 2% of remaining allocation per month
- **Full transparency:** All grant proposals and disbursements recorded on-chain

---

## 17. Governance Economics

### 17.1 Bi-Cameral Governance

Aethelred implements a bi-cameral governance structure:

- **House of Tokens** — Voting power proportional to staked AETHEL (1 token = 1 vote).
- **House of Sovereigns** — Validator-level representation independent of stake size.

This design prevents plutocratic capture while maintaining Sybil resistance.

### 17.2 Governance Parameters

| Parameter | Bootstrap Phase | Active Phase |
|-----------|----------------|-------------|
| Voting Period | 3.5 days (50,400 blocks) | 7 days (100,800 blocks) |
| Quorum | 33% | 40% |
| Pass Threshold | 50% | 50% |
| Veto Threshold | 33% | 33% |
| Maximum Active Proposals | 10 | 20 |
| Minimum Deposit | 100,000 AETHEL | 100,000 AETHEL |
| Governance Activation | 2 weeks post-genesis | Automatic at maturity |

### 17.3 Parameter Governance Tiers

Network parameters are classified by sensitivity with progressively higher quorums for modification:

| Tier | Override Quorum | Examples |
|------|----------------|---------|
| Mutable | 67% (standard) | Job timeout, max jobs per block, base fee |
| Locked | 80% (elevated) | Fee distribution split, slashing penalty, consensus threshold |
| Critical | 90% (supermajority) | TEE attestation requirement |
| Immutable | Cannot be changed | AllowSimulated=false (one-way production gate) |

### 17.3b Voting Power Multipliers

Stakeholders who lock their AETHEL for extended periods receive boosted governance voting power:

| Lock Duration | Voting Power Multiplier |
|---|---|
| 90 days | 1.0x |
| 180 days | 1.25x |
| 365 days | 1.6x |
| 730 days (2 years) | 2.0x |

This incentivizes long-term commitment and prevents governance manipulation through short-term token accumulation.


### 17.4 Governance & Control Summary

| Category | Structure | Signers | Decision Rights | Timelock |
|----------|-----------|---------|----------------|----------|
| Insurance Fund | 3-of-5 Multi-sig | 2 Team + 2 Advisors + 1 Auditor | Slashing appeals; hack indemnity | 7 days for >10M tokens |
| Contingency Reserve | Team + Advisor Majority | Core team + board members | Emergency funds; strategic pivots | 30 days |
| Treasury | Team-controlled | CEO + CFO + CTO | Operational expenses; MM loans | 14 days for >$500K |

### 17.5 Council

| Parameter | Value |
|-----------|-------|
| Council Size | 9 members |
| Term Length | 1 year |

---

## 18. Bridge Economics

### 18.1 Architecture

Aethelred implements a lock-and-mint bridge for cross-chain asset transfers between Ethereum and the Aethelred L1, with multi-signature relayer consensus.

### 18.2 Bridge Parameters

| Parameter | Value |
|-----------|-------|
| Minimum Deposit | 0.01 ETH |
| Maximum Single Deposit | 100 ETH |
| Maximum Deposit per Hour | 1,000 ETH |
| Maximum Withdrawal per Hour | 1,000 ETH |
| Challenge Period | 7 days |
| Ethereum Finality | 64 confirmations (~12.8 minutes) |
| Emergency Withdrawal Cap | 50 ETH |
| Emergency Timelock | 48 hours (configurable: 24h–14d) |
| Guardian Multi-Sig | 2-of-N |
| Relayer Consensus | Configurable (default: 67%) |
| Per-Block Mint Ceiling | 10 ETH |
| Deposit Cancellation Window | 1 hour |
| Upgrade Timelock | Minimum 27 days |

### 18.3 Rate Limiting

The bridge implements defence-in-depth rate limiting across multiple dimensions:

1. **Per-period limits:** 1,000 ETH per hour for both deposits and withdrawals.
2. **Per-transaction limits:** 0.01 ETH minimum, 100 ETH maximum per deposit.
3. **Per-block mint ceiling:** 10 ETH maximum mintable per block, preventing burst attacks.
4. **Emergency withdrawal cap:** 50 ETH maximum per emergency operation.

### 18.4 Challenge Mechanism

All withdrawals are subject to a 7-day challenge period during which guardians can flag and halt fraudulent withdrawals. The challenge mechanism uses a vote-snapshot approach — the threshold required is the stricter of the snapshot at proposal time or the current threshold, preventing manipulation via relayer churn.

---

## 19. Institutional Stablecoin Infrastructure

### 19.1 Overview

Aethelred provides a zero-liquidity-pool stablecoin routing infrastructure designed for institutional flows. Unlike AMM-based bridges, Aethelred routes stablecoin transfers through issuer-authorised channels (Circle CCTP V2 for USDC, TEE-attested issuer mints for others).

### 19.2 Routing Types

| Route | Mechanism | Use Case |
|-------|-----------|----------|
| CCTP V2 | Circle burn-and-mint | USDC cross-chain transfers |
| TEE Issuer Mint | Issuer-gated TEE attestation | Non-CCTP stablecoins |

### 19.3 Risk Management

| Control | Description |
|---------|-------------|
| Per-Epoch Mint Ceiling | Maximum stablecoin mintable per 24-hour epoch |
| Daily Transaction Limit | Maximum transaction volume per day |
| Hourly Outflow Velocity | Maximum hourly outflow as % of circulating supply |
| Daily Outflow Velocity | Maximum daily outflow as % of circulating supply |
| Proof-of-Reserve Monitoring | Chainlink oracle deviation threshold triggers circuit breaker |
| Oracle Heartbeat | Maximum oracle staleness before automatic pause |

### 19.4 Governance Keys

Five institutional governance keys control the stablecoin infrastructure, with a 3-of-5 threshold for critical operations:

| Key | Holder |
|-----|--------|
| Issuer Key | Stablecoin issuer |
| Issuer Recovery Key | Issuer backup (distinct from primary) |
| Foundation Key | Aethelred Foundation |
| Auditor Key | External auditor / custodian |
| Guardian Key | Independent guardian (distinct from all others) |

### 19.5 Relayer Bonding

Relayers must post a bond of **500,000 AETHEL** to participate in stablecoin message relay. Bonds can be slashed for relayer misbehaviour, creating strong economic alignment.

---

## 20. AI Compute Market Economics

### 20.1 Job Lifecycle

Every AI inference job on Aethelred follows an on-chain lifecycle:

```
Submitted -> Assigned -> Proving -> Verified -> Settled
                                         \-> Failed
                                    \-> Cancelled
```

### 20.2 Job Parameters

| Parameter | Value |
|-----------|-------|
| Maximum Jobs per Block | 25 (~4.2 jobs/second at 6s blocks) |
| Maximum Jobs per Validator | 3 concurrent |
| Job Timeout | 50 blocks (~5 minutes) |
| Job Expiry | 14,400 blocks (~24 hours) |
| Minimum Validators per Job | 3 |
| Maximum Retries | 3 |
| Verification Reward | 100 uaethel per validator |

### 20.3 Priority Scheduling

Jobs are scheduled using a max-heap priority queue with aging:

```
effective_priority = base_priority + (wait_blocks * priority_boost_per_block)
```

Failed jobs receive a +10 priority boost per retry, ensuring they are eventually processed. After 3 retries, a job is permanently marked as failed.

### 20.4 Verification Types

| Type | Description | Security Level |
|------|-------------|---------------|
| TEE | Trusted Execution Environment attestation (SGX, SEV, Nitro, TrustZone) | High |
| ZKML | Zero-knowledge proof of ML inference (EZKL, RISC Zero, Plonky2, Halo2, Groth16) | High |
| Hybrid | TEE + ZKML cross-validation | Highest |

### 20.5 Digital Seal

When sufficient validators (>= 2/3 + 1) attest to a computation result, a **Digital Seal** is minted — an immutable, on-chain proof of verifiable AI inference. Seals are:

- TEE Precompile (Trusted Execution Environment): Address `0x0400`
- ZKP Precompile (Zero-Knowledge Proof): Address `0x0300`
- Relayable across IBC-compatible chains on port `aethelred.seal`
- Queryable via the `IAethelredOracle` interface

### 20.6 Tensor Precompiles

### 20.7 Job Category Multipliers

Different categories of AI inference jobs have different computational complexity and value. Validators receive category-based reward multipliers:

| Category | Multiplier | Notes |
|----------|-----------|-------|
| Healthcare & Biotech | 1.8x | High-complexity medical AI models |
| Scientific Research | 1.6x | Physics simulations, climate modeling |
| Finance & Risk | 1.4x | Fraud detection, risk assessment |
| General Inference | 1.0x | Standard LLM and general-purpose models |

Aethelred provides native EVM precompiles for AI computation at addresses `0x1000`–`0x1FFF`, with logarithmic gas scaling:

```
gas_cost = base_gas * log2(tensor_size)
```

This sublinear gas model makes large-scale AI inference economically viable on-chain.

---

## 21. Validator Economics

### 21.1 Revenue Streams

A validator's total revenue is composed of:

1. **PoUW rewards** — 25,000,000 AETHEL/month distributed across all active validators.
2. **Job fees** — 40% of all inference fees, distributed equally and reputation-scaled (Section 12).
3. **Verification rewards** — 100 uaethel per verified job.
4. **Compute bonuses** — 1.5x multiplier for TEE-equipped validators.
5. **Commission** — 5-20% of delegator rewards.

### 21.2 Cost Structure

Validators incur costs for:

- **Hardware:** TEE-capable servers (SGX, SEV, or Nitro).
- **Staking capital:** 100,000 AETHEL minimum, with opportunity cost.
- **Bandwidth and storage:** Block propagation and state storage.
- **Operational overhead:** Monitoring, key management, HSM integration.

### 21.3 Validator Onboarding

New validators undergo a structured onboarding process with an 80-point minimum threshold across:

- Hardware verification (TEE attestation)
- Stake deposit confirmation
- Consensus participation readiness
- Network connectivity verification

---

## 22. Economic Security Analysis

### 22.1 BFT Security Assumption

The protocol assumes **at least 2/3 of staked value is controlled by honest validators**. This is the standard CometBFT/Tendermint safety threshold.

### 22.2 Attack Cost Analysis

At the target 55% staking ratio (5.5 billion AETHEL staked) and $0.10/AETHEL:

| Attack | Stake Required | Cost at TGE ($0.10) | Consequence |
|--------|---------------|---------------------|-------------|
| BFT Attack (>1/3 control) | 1.83B AETHEL | $183,000,000 | 100% slash = total loss |
| Majority Attack (>1/2 control) | 2.75B AETHEL | $275,000,000 | 100% slash = total loss |
| Supermajority (>2/3 control) | 3.67B AETHEL | $367,000,000 | 100% slash = total loss |

The 33% validator concentration cap (Section 13.2) ensures no single entity can approach the BFT threshold without Sybil-attacking the system with multiple validator identities, which is detectable.

### 22.3 Security Invariants

The protocol enforces 10 on-chain security invariants (SI-01 through SI-10):

1. **SI-01:** Total supply never exceeds the hard cap.
2. **SI-02:** Fee distribution sums to exactly 10,000 BPS.
3. **SI-03:** Vested amounts are monotonically non-decreasing.
4. **SI-04:** Contract solvency — vesting contract holds sufficient tokens for all unvested amounts.
5. **SI-05:** Slashing deterrence ratio > 1 for all attack vectors.
6. **SI-06:** Consensus threshold > 66% (BFT-safe).
7. **SI-07:** No double-spending across bridge operations.
8. **SI-08:** Rate limits enforced on all bridge operations.
9. **SI-09:** Per-block mint ceilings maintained.
10. **SI-10:** AllowSimulated = false in production (immutable one-way gate).

### 22.4 Threat Model

The economic security model is validated against five adversary classes:

1. **Rational Economic Attacker** — Motivated by profit; deterred by slashing.
2. **State-Level Adversary** — Motivated by censorship; mitigated by decentralisation requirements and validator distribution.
3. **MEV Extractor** — Mitigated by VRF-based job assignment and priority-based scheduling.
4. **Bridge Attacker** — Mitigated by 7-day challenge periods, rate limits, and guardian oversight.
5. **Cryptographic Adversary** — Mitigated by hybrid post-quantum cryptography (Section 23).

---

## 23. Post-Quantum Cryptographic Considerations

### 23.1 Hybrid Signature Scheme

Aethelred implements a hybrid cryptographic architecture that provides both classical and quantum resistance:

| Algorithm | Security Level | Purpose |
|-----------|---------------|---------|
| ECDSA secp256k1 | 128-bit classical | Backward compatibility with Ethereum ecosystem |
| Dilithium3 (ML-DSA-65) | 128-bit quantum | Quantum-resistant digital signatures |
| ML-KEM-1024 | 128-bit quantum | Quantum-resistant key encapsulation |

### 23.2 Economic Implications

- **Larger signatures** increase transaction sizes and therefore base gas costs.
- **Dual verification** (ECDSA + Dilithium) increases verification overhead but provides defence-in-depth.
- **HSM requirement** for mainnet validators (AWS CloudHSM, Thales Luna, YubiHSM 2) adds operational costs but ensures key material security.
- **Panic mode** can drop to Dilithium-only verification if ECDSA is compromised, maintaining network security at the cost of Ethereum compatibility.

### 23.3 Key Management

All validator keys implement `ZeroizeOnDrop` — cryptographic key material is securely erased from memory when no longer needed, preventing cold-boot and memory-scraping attacks.

---

## 24. Formal Verification & Audit

### 24.1 Audit Engagements

| Auditor | Scope | Status |
|---------|-------|--------|
| Trail of Bits | Smart contracts, consensus, cryptography | Engaged — 2 audit cycles planned |
| OtterSec | Smart contracts, bridge, tokenomics | Engaged — 2 audit cycles planned |
| Internal Security Review | Full protocol (Go/Solidity/Rust) | Complete — 27 findings, all remediated |
| External VRF Consultant | VRF + protocol review | Complete — RS-01 (Critical) fixed |

### 24.2 Verification Coverage

| Contract | Verification Tool | Status |
|----------|------------------|--------|
| AethelredToken.sol | Certora / Halmos | Tier 1 (pre-mainnet) |
| AethelredVesting.sol | Certora / Halmos | Tier 1 (pre-mainnet) |
| AethelredBridge.sol | Certora / Halmos | Tier 1 (pre-mainnet) |
| SovereignGovernanceTimelock.sol | Certora / Halmos | Tier 1 (pre-mainnet) |
| Tokenomics (Rust) | Kani | Tier 2 |
| VRF (Rust) | Kani | Tier 2 |
| Consensus Protocol | TLA+ | Tier 3 |

### 24.3 Verified Invariants

**Token Contract (5 invariants):**
- Total supply remains constant after initialisation
- Blacklist enforcement on all transfer paths
- Circulating supply bounded by total supply
- Bridge mint respects supply cap
- Burn tracking is consistent

**Vesting Contract (4 invariants):**
- Monotonicity of vested amounts
- Released amount bounded by vested amount
- Contract solvency at all times
- TGE timing correctness

**Bridge Contract (3 invariants):**
- No double withdrawal
- Rate limit enforcement
- Per-block ceiling maintenance

### 24.4 Internal Audit Results

| Severity | Findings | Status |
|----------|---------|--------|
| Critical | 3 | All remediated and closed |
| High | 5 | All remediated and closed |
| Medium | 8 | All remediated and closed |
| Low | 7 | All remediated and closed |
| Informational | 6 | All remediated and closed |
| **Total** | **27** | **100% closed** |

### 24.5 Test Coverage

| Suite | Tests | Coverage |
|-------|-------|---------|
| Tokenomics Model | 57 tests | Emission, staking, fees, slashing, vesting |
| Audit Regression | Targeted | Overflow protection (C-01), off-by-one (H-03) |
| Ecosystem Launch | 44 tests | Launch readiness, validator onboarding |
| Job State Machine | Comprehensive | State transitions, deterministic IDs, expiry |
| Total Required for Launch | 435+ tests | Full protocol |

---

## 25. Mainnet Launch Economics

### 25.1 Launch Readiness

Mainnet launch requires passing 10 production readiness checks:

| Check | Description | Blocking |
|-------|-------------|----------|
| R-01 | No unresolved critical audit findings | Yes |
| R-02 | All module invariants pass | Yes |
| R-03 | Module parameters valid | Yes |
| R-04 | AllowSimulated disabled (production mode) | Yes |
| R-05 | Consensus threshold > 66% (BFT-safe) | Yes |
| R-06 | Fee distribution BPS sum = 10,000 | Yes |
| R-07 | All 435+ unit tests pass | Yes |
| R-08 | Upgrade/migration infrastructure tested | No |
| R-09 | Audit logging framework operational | No |
| R-10 | All open items documented with mitigations | Yes |

### 25.2 Go/No-Go Scoring

| Category | Weight |
|----------|--------|
| Security | 30% |
| Performance | 20% |
| Economics | 15% |
| Operations | 15% |
| Ecosystem | 10% |
| Governance | 10% |

- **Score >= 80:** GO
- **Any blocking criterion failed:** NO-GO
- **Otherwise:** CONDITIONAL-GO

### 25.3 Chain Maturity Timeline

| Phase | Duration | Governance |
|-------|----------|-----------|
| Launch | 0–2 weeks | Bootstrap governance (33% quorum, 10 max proposals) |
| Early Operations | 2–6 weeks | Transitional monitoring |
| Stable | 6–12 weeks | Full governance activation (40% quorum, 20 max proposals) |
| Mature | 12+ weeks | Full decentralisation |

---

## 26. Key Dates & Milestones

| Date | Milestone | Type | Details |
|------|-----------|------|---------|
| Mar–Apr 2026 | Seed Round Close | Fundraising | $1M at $100M FDV |
| Mar 2026 | Discord / X / Telegram Launch | Community | Social media activation; Seals points begin |
| May 1, 2026 | Testnet Launch | Technical | Public testnet; validator onboarding; bug bounty live |
| Jun–Jul 2026 | Echo Round | Fundraising | $6M at $150M FDV via Coinbase Echo |
| Sep–Oct 2026 | Strategic Round | Fundraising | $3.75M at $250M FDV |
| Nov 2026 | Exchange Round | Fundraising | $5.25M at $300M FDV (Binance primary; Bybit/OKX backup) |
| Nov 2026 | Airdrop Snapshot | Tokenomics | Final Seals points tally |
| Dec 7–10, 2026 | TGE | Token Generation | At Abu Dhabi Finance Week; airdrop distribution; exchange listings |
| Q1 2027 | Mainnet Launch | Technical | Full network launch; dApp ecosystem live |

---

## 27. Competitive Benchmarks

### 27.1 Comparable L1 Launches

| Project | Team % | TGE Float | Airdrop % | FDV at TGE | Outcome |
|---------|--------|----------|-----------|------------|---------|
| Sui | 20% | ~5% | 6% | $2B | Successful but community sought larger airdrop |
| Aptos | 20% | ~13% | 51% (incl. testnet) | $1B | Significant sell pressure due to high float |
| Celestia | 20% | ~20% | 7.4% | $300M | Well-received; careful community targeting |
| Arbitrum | ~27% | ~12% | 12.75% | $1.4B | Successful; 2+ years of usage before TGE |
| Monad | TBD | TBD | TBD | TBD | Highly anticipated; similar structure expected |
| **Aethelred** | **20%** | **6.3%** | **7%** | **$1B (target)** | **Balanced; lessons learned from above** |

### 27.2 Key Design Choices vs. Peers

| Decision | Aethelred Approach | Rationale |
|----------|-------------------|-----------|
| TGE Float | 6.3% (conservative) | Avoids Aptos-style sell pressure; closer to Sui model |
| Team Allocation | 20% (market standard) | Matches Sui, Aptos, Celestia exactly |
| Team Cliff | 6 months (shorter) | Provides operational liquidity; balanced with 48-month total vest |
| Airdrop | 7% with points program | Between Sui (6%) and Arbitrum (12.75%); avoids Aptos over-distribution |
| Investor Allocation | 5.5% (conservative) | Less dilutive than peers; deep discount maintains alignment |
| FDV at TGE | $1B (moderate) | Between Celestia ($300M) and Sui ($2B); room for growth |

---

## 28. Risk Factors & Mitigations

| Risk | Likelihood | Impact | Mitigation | Owner |
|------|-----------|--------|-----------|-------|
| TGE price dump | Medium | High | 6.3% float is defensible; MM support with $37.5M ammunition; 80% Public Sales locked | Ops Team |
| Geopolitical (UAE conflict) | Medium | Medium | Virtual TGE backup plan; alternative jurisdictions identified | CEO |
| Team hiring difficulty | Low | High | 20% allocation matches market standard; 6-month cliff provides early liquidity | CEO |
| Exchange listing failure | Low | High | Binance primary + Bybit/OKX contingency; DEX backup plan | BD Team |
| Testnet delay | Medium | Medium | Buffer built into timeline; contractor support available (Protofire) | CTO |
| Smart contract exploit | Low | Catastrophic | 2 audit cycles (Trail of Bits + OtterSec); Insurance Fund; formal verification | Security Lead |
| Regulatory uncertainty | Medium | Medium | ADGM engagement from day one; legal counsel on retainer; compliance-first token design | General Counsel |

---

## 29. Long-Term Economic Sustainability

### 29.1 Revenue Model

Aethelred's long-term economic sustainability is powered by a fee-driven economy:

1. **AI inference fees** scale with network utilisation and the growing demand for verifiable AI computation.
2. **Bridge fees** from cross-chain asset transfers.
3. **Stablecoin routing fees** from institutional flows.
4. **Tensor precompile gas** from on-chain AI operations.

### 29.2 Equilibrium State

At economic maturity, the protocol targets:

- **Inflation:** 0% (fixed supply)
- **Burn rate:** Net deflationary, increasing with utilisation
- **Staking ratio:** ~55% of circulating supply
- **Validator yield:** 3–6% APY from PoUW rewards + fee revenue
- **Treasury growth:** Self-sustaining from fee revenue

### 29.3 Supply Trajectory

With a fixed supply and multiple burn mechanisms, AETHEL follows a structurally deflationary trajectory:

- **Years 1–10:** PoUW rewards distribute 300M AETHEL/year from the pre-minted pool. Burns offset a growing proportion.
- **Year 10+:** PoUW pool exhausted. Validators transition to fee-only revenue. With sufficient network utilisation, fee revenue alone sustains the validator set.
- **Long-term:** Total supply monotonically decreases. The token becomes scarcer as the network becomes more useful.

The total supply is bounded above by the hard cap of 10 billion AETHEL and bounded below by the cumulative burn total, which grows monotonically.

---

## 30. Regulatory Compliance Design

### 30.1 OFAC/Sanctions Compliance

The token contract implements a compliance module with:

- **Address blacklisting** — Blocks all transfers to/from sanctioned addresses.
- **Batch blacklisting** — Up to 200 addresses per transaction for efficiency.
- **Compliance burns** — Regulatory token seizure with mandatory `bytes32` reason code and full on-chain audit trail via `ComplianceSlash` events.
- **Transfer restrictions** — Pre-TGE lock with whitelist exemptions for operational addresses.

### 30.2 Governance Timelocks

All critical administrative actions are subject to timelocks:

| Action | Minimum Timelock |
|--------|-----------------|
| Contract upgrades | 27 days |
| Governance key rotation | 7 days |
| Ecosystem fund disbursement | 48 hours |
| Emergency bridge withdrawal | 48 hours |
| Contingency reserve access | 30 days |

### 30.3 Multi-Signature Requirements

Production deployment enforces that all administrative addresses are smart contracts (not EOAs), ensuring multi-signature governance at every level:

- Token admin: Multi-sig contract
- Bridge guardians: 2-of-N multi-sig
- Ecosystem fund: 4-of-7 multi-sig
- Stablecoin governance: 3-of-5 multi-sig
- Insurance fund: 3-of-5 multi-sig
- Governance key rotation: Dual-signature (issuer + foundation)

### 30.4 Audit Trail

Every economically significant action emits indexed events for off-chain monitoring and regulatory reporting:

- Token mints, burns, and transfers
- Compliance actions with reason codes
- Bridge deposits, withdrawals, and challenges
- Governance proposals, votes, and executions
- Slashing events with full evidence
- Vesting claims and schedule modifications

---

## Appendix A — Parameter Reference

### A.1 Token Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Total Supply | 10,000,000,000 AETHEL | `AethelredToken.sol:TOTAL_SUPPLY_CAP` |
| Supply Model | Fixed (no inflation) | Tokenomics Final v1.0 |
| Cosmos Denomination | uaethel (6 decimals) | `tokenomics.go` |
| EVM Denomination | wei (18 decimals) | `AethelredToken.sol` |
| Scale Factor | 10^12 | `tokenomics.go:UaethToWeiScaleFactor` |
| Chain ID (Cosmos) | aethelred-1 | `mainnet_params.go` |
| Chain ID (EVM) | 8821 | Protocol specification |
| TGE Target Price | $0.10 / AETHEL | Tokenomics Final v1.0 |
| TGE FDV | $1,000,000,000 | Tokenomics Final v1.0 |

### A.2 Allocation Parameters

| Category | Allocation | TGE Unlock | Cliff | Total Vest | Source |
|----------|-----------|-----------|-------|-----------|--------|
| PoUW Rewards | 30% (3B) | 0% | None | 120 months | Tokenomics Final v1.0 |
| Core Contributors | 20% (2B) | 0% | 6 months | 48 months | Tokenomics Final v1.0 |
| Ecosystem & Grants | 15% (1.5B) | 2% | 6 months | 54 months | Tokenomics Final v1.0 |
| Treasury & MM | 6% (600M) | 25% | None | 36 months | Tokenomics Final v1.1 |
| Public Sales | 7.5% (750M) | 20% | None | 18 months | Tokenomics Final v1.0 |
| Airdrop (Seals) | 7% (700M) | 25% | None | 12 months | Tokenomics Final v1.0 |
| Strategic / Seed | 5.5% (550M) | 0% | 12 months | 36 months | Tokenomics Final v1.0 |
| Insurance Fund | 5% (500M) | 10% | None | 30 months | Tokenomics Final v1.0 |
| Contingency Reserve | 4% (400M) | 0% | 12 months | TBD | Tokenomics Final v1.0 |

### A.3 Fee Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Base Fee | 1,000 uaethel | `tokenomics.go:BaseFeeUAETH` |
| Max Multiplier | 50,000 BPS (5x) | `tokenomics.go:MaxMultiplierBps` |
| Congestion Threshold | 7,000 BPS (70%) | `tokenomics.go:CongestionThresholdBps` |
| Validator Rewards | 4,000 BPS (40%) | `fee_distribution.go` |
| Treasury Share | 3,000 BPS (30%) | `fee_distribution.go` |
| Burn Share | 2,000 BPS (20%) | `fee_distribution.go` |
| Insurance Share | 1,000 BPS (10%) | `fee_distribution.go` |

### A.4 Staking Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Min Validator Stake | 100,000 AETHEL | `mainnet-genesis.json` |
| Min Compute Stake | 10,000 AETHEL | `mainnet-genesis.json` |
| Min Delegator Stake | 100 AETHEL | `mainnet-genesis.json` |
| Max Validators | 100 | `tokenomics.go:MaxValidators` |
| Min Commission | 500 BPS (5%) | `tokenomics.go:MinCommissionBps` |
| Max Commission | 2,000 BPS (20%) | `tokenomics.go:MaxCommissionBps` |
| Unbonding (Validator) | 302,400 blocks (21 days) | `tokenomics.go:UnbondingPeriodBlocks` |
| Redelegation Cooldown | 100,800 blocks (7 days) | `tokenomics.go:RedelegationCooldownBlocks` |
| Concentration Cap | 3,300 BPS (33%) | `tokenomics.go` |

### A.5 Slashing Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Minor Fault | 50 BPS (0.5%) | `tokenomics.go` |
| Major Fault | 1,000 BPS (10%) | `tokenomics.go` |
| Fraud | 5,000 BPS (50%) | `tokenomics.go` |
| Critical Byzantine | 10,000 BPS (100%) | `tokenomics.go` |
| Double Sign | 5,000 BPS (50%) | `tokenomics.go:DoubleSignSlashBps` |
| Downtime | 100 BPS (1%) | `tokenomics.go:DowntimeSlashBps` |
| Downtime Window | 10,000 blocks | `tokenomics.go:DowntimeWindowBlocks` |
| Min Signed per Window | 5,000 BPS (50%) | `tokenomics.go:MinSignedPerWindowBps` |

### A.6 Bridge Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Min Deposit | 0.01 ETH | `AethelredBridge.sol` |
| Max Deposit | 100 ETH | `AethelredBridge.sol` |
| Challenge Period | 7 days | `AethelredBridge.sol` |
| ETH Confirmations | 64 blocks | `AethelredBridge.sol` |
| Emergency Timelock | 48 hours | `AethelredBridge.sol` |
| Guardian Approvals | 2-of-N | `AethelredBridge.sol` |
| Upgrade Timelock | 27 days minimum | `AethelredBridge.sol` |
| Per-Block Mint Ceiling | 10 ETH | `AethelredBridge.sol` |

### A.7 Fundraising Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Seed Price | $0.010 / AETHEL | Tokenomics Final v1.0 |
| Echo Price | $0.015 / AETHEL | Tokenomics Final v1.0 |
| Strategic Price | $0.025 / AETHEL | Tokenomics Final v1.0 |
| Exchange Price | $0.030 / AETHEL | Tokenomics Final v1.0 |
| Weighted Average | $0.0194 / AETHEL | Tokenomics Final v1.0 |
| Total Raised | $16,000,000 | Tokenomics Final v1.0 |
| Tokens Sold | 825,000,000 (8.25%) | Tokenomics Final v1.0 |

### A.8 Governance Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Standard Quorum | 67% | `mainnet_params.go` |
| Elevated Quorum | 80% | `mainnet_params.go` |
| Critical Quorum | 90% | `mainnet_params.go` |
| Bootstrap Voting Period | 50,400 blocks (3.5 days) | `post_launch.go` |
| Active Voting Period | 100,800 blocks (7 days) | `post_launch.go` |
| Grant Quorum | 33% | `tokenomics_treasury_vesting.go` |
| Insurance Fund Timelock (>10M) | 7 days | Tokenomics Final v1.0 |
| Contingency Reserve Timelock | 30 days | Tokenomics Final v1.0 |
| Treasury Timelock (>$500K) | 14 days | Tokenomics Final v1.0 |

---

## Appendix B — Mathematical Proofs

### B.1 Supply Boundedness

**Theorem:** Under the fixed supply model, total supply is monotonically non-increasing.

**Proof:** The total supply at any time `t` is:

```
S(t) = S_0 - B(t)
```

where `S_0 = 10,000,000,000` is the genesis supply and `B(t)` is the cumulative burn total. Since burns are irreversible (`B(t) >= B(t-1)` for all `t`) and no new tokens can be minted beyond the genesis supply (enforced by `TOTAL_SUPPLY_CAP`), `S(t)` is monotonically non-increasing. The token is structurally deflationary.

### B.2 Slashing Deterrence

**Theorem:** For all defined attack vectors, the deterrence ratio exceeds 1.

**Proof:** For each slashing tier, the slash amount is:

```
slash = staked * slash_bps / 10,000
```

The maximum potential gain from any single-block attack is bounded by:

```
max_gain <= PoUW_reward_per_block + max_job_fee * max_jobs_per_block
         = (25,000,000 / blocks_per_month) + base_fee * 5x * max_jobs
```

At minimum stake (100,000 AETHEL) and fraud tier (50% slash = 50,000 AETHEL), the deterrence ratio:

```
ratio = 50,000 / max_gain >> 1
```

since `max_gain` is on the order of single AETHEL per block.

### B.3 Vesting Monotonicity

**Theorem:** For any vesting schedule, `vested(h) <= vested(h+1)` for all block heights `h`.

**Proof:** The vesting function is piecewise:
1. For `h < cliff`: `vested = TGE_amount` (constant)
2. For `cliff <= h < end`: `vested = TGE + cliff_amount + remaining * (h - cliff) / (end - cliff)` (monotonically increasing, since `remaining >= 0` and the fraction increases)
3. For `h >= end`: `vested = total` (constant)

At the transition points, continuity is ensured by the floor/ceiling clamping logic. Formally verified via Kani proof harness.

---

*This document represents the authoritative tokenomics specification for the Aethelred protocol. All allocation and vesting parameters are derived from the Aethelred Tokenomics Final v1.1. All technical parameters are derived from the canonical Go implementation, Solidity smart contracts, and Rust VM modules. In case of discrepancy between this document and the code, the code is authoritative for technical parameters; the Tokenomics Final v1.1 is authoritative for allocation and vesting parameters.*

---

**Document Control**

| Field | Value |
|-------|-------|
| Version | 2.0 |
| Date | March 11, 2026 |
| Prepared By | Aethelred Foundation |
| Approved By | Ramesh Tamilselvan, CEO |
| Next Review | Post-Seed Close |
| Change Log | v2.0: Ticker updated to AETHEL; minimum validator stake updated to 100,000; core contributor vesting recalculated; post-quantum parameters updated to ML-KEM-1024; category multipliers and voting power multipliers added; precompile addresses updated. |

---

**Aethelred Foundation**
Abu Dhabi Global Market, Al Maryah Island
Abu Dhabi, United Arab Emirates
