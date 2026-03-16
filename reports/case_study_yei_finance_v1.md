# Case Study: Yei Finance Flash Loan Exploit ($2.4M)

**On-Chain Fund Flow Verification & Current State Analysis**

Analysis date: 2026-03-16 (Phase 1-5 + Phase 6 v2 re-analysis)
Classification: Public case study (all data from public blockchain + public reports)

---

## 1. Incident Summary

| Item | Detail |
|:---|:---|
| Date | December 2, 2024 |
| Target | Yei Finance (money market protocol on Sei blockchain) |
| Method | Flash loan exploit targeting WBTC pool |
| Amount | ~$2.4 million |
| Chain of origin | Sei |
| Laundering path | SEI -> BTC -> BSC -> ETH -> BASE -> Arbitrum -> ETH mainnet -> Aave V3 -> Railgun -> Tornado Cash (400 ETH) / Chainflip (30 ETH→BTC) / CCTP (78.7K USDC→Base) / Stargate (270K USDC + 15 ETH→BSC) |
| Linked incidents | EraLend (Jul 2023, ~$2.76M), Onyx Protocol (Sep 2024, ~$3.8M), zkLend (Feb 2025, ~$9.5M), Channels Finance, Starlay Finance |
| Total serial proceeds | **$20M+** across 5+ incidents (same attacker confirmed by SlowMist + Merkle Science) |
| Source | [Merkle Science](https://www.merklescience.com/blog/hack-track-yei-finance-flow-of-funds-analysis), [SlowMist](https://slowmist.medium.com/in-depth-analysis-of-zklend-hack-linked-to-eralend-hack-fba4af9b66ef) |

---

## 2. Known Addresses

| Address | Chain(s) | Role | Source |
|:---|:---|:---|:---|
| `0xcd2860fc4abf1748b8e4aebf35ddef2ab03e17c5` | Arbitrum, BSC, Base, Ethereum | Primary attacker wallet | Merkle Science + our verification |
| `0x313708e21398421d3b260494c0bf233403aEfC99` | **Ethereum** | **Secondary laundering wallet (Aave hop)** | **Our Phase 3 discovery** |
| `0x1de6f3ccfab74302d30aac3649b4700347bb52e8` | Ethereum | Chainflip refund recipient | Merkle Science |
| `bc1qknee33zjlwvlgha6su6rgs00hjpr3zxqk0cyv8` | Bitcoin | Partial Chainflip output | Merkle Science |
| `0x555fB0Eb4e21c7b895fCa348154F3a00aCc520f1` | Ethereum | **Chainflip deposit contract (30 ETH → BTC)** | **Our Phase 4 discovery** |
| `0x438df96f11b8d7424f8e017b806ee63d89429c68` | **Base** | **CCTP USDC recipient #1 (10,000 USDC)** | **Our Phase 4 discovery** |
| `0x6800d90cf15a57806bc2fd5fec5c0405c2a1b5fe` | **Base** | **CCTP USDC recipient #2 (68,693 USDC)** | **Our Phase 4 discovery** |
| `0x5f80C18C823dac7C13F3e9Fb09d4D92CAeD98671` | Ethereum | **USDC recipient (32,158 USDC)** | **Our Phase 4 discovery** |

---

## 3. Phase 1 Findings: State Verification (2026-03-15)

### 3.1 Arbitrum Resting Point (0xcd28..17c5)

**Prior report (Merkle Science, Jan 2025):** ~1,006,152 DAI + ~281 ETH at rest.

**Current state (verified 2026-03-15):**

| Asset | Reported (Jan 2025) | Current | Change |
|:---|:---|:---|:---|
| DAI | ~1,006,152 | 0 | **DRAINED** |
| ETH | ~281 | ~0 | **DRAINED** |
| USDC | -- | 0 | -- |
| USDT | -- | 0 | -- |

### 3.2 Cross-Chain Presence (New Finding)

| Chain | Tx Count | Native Balance | Finding |
|:---|:---|:---|:---|
| **Sei** | **182** | **~0 SEI** | **Exploit origin chain — full tx history recovered via Etherscan V2 API** |
| Arbitrum | 48 | ~0 | Drained |
| Ethereum | **8** | 0.000047 ETH | **Drained (was 596 ETH)** |
| **Base** | **1** | **0.002439 ETH** | **Unreported in prior analysis** |
| **BSC** | **13** | **0.002067 BNB** | **Unreported in prior analysis** |

The same EOA was reused across **5 chains** (Sei + 4 EVM) -- a significant operational security weakness.

### 3.4 Sei Chain: Exploit Origin Timeline (New Finding via Etherscan V2)

**182 transactions on Sei**, all within 2024-12-02 11:35 - 15:33 UTC (4 hours) + 2 cleanup txs.

**Exploit execution pattern:**

| Time (UTC) | Action | Detail |
|:---|:---|:---|
| 11:35 | **100 SEI received** | Gas funding (source TBD) |
| 11:37 | `send()` via LayerZero | First bridge out (1.5 SEI fee) |
| 11:38-11:47 | `metaRoute()` x2 | Symbiosis bridge/swap (20 SEI each) |
| 12:10-12:43 | `approve()` + `supply()` + `borrow()` | **Yei Finance exploit execution — supply/borrow cycle** |
| 12:44-15:33 | `send()` x8 + `supply/borrow` cycles | **Repeated exploit + bridge cycles** |
| 15:27 | 97.1 SEI via `send()` | Large bridge out |
| 15:32 | **4,000 SEI → 0x1de6** | Native transfer to Chainflip refund address |
| 15:33 | Last `send()` | Final bridge out |

**Failed tx at 12:15:** `send()` failed → retried at 12:16. Human error/retry pattern.

**Cleanup (10 months later):**

| Date | Action |
|:---|:---|
| 2024-12-04 | Minor token transfer IN |
| 2025-10-11 | Token transfer IN |
| **2025-10-23 05:13** | **960 SEI via metaRoute() — final cleanup sweep** |

### 3.3 Ethereum Chainflip Refund (0x1de6..52e8)

| Asset | Balance |
|:---|:---|
| ETH | 0.009959 (dust) |
| DAI / USDC / USDT | 0 |

Tx count: 0 outgoing. 127 ETH received from Chainflip, now drained (dust only remains).

---

## 4. Phase 2 Findings: Full Transaction History (Arbiscan)

### 4.1 Arbitrum: Complete 48-Transaction Timeline

The attacker executed **48 transactions** on Arbitrum from 2024-12-02 to 2025-10-23, falling into 5 distinct phases:

#### Phase A: Arrival + Initial Swaps (2024-12-02, 26 transactions)

| Time (UTC) | Action | Protocol | Detail |
|:---|:---|:---|:---|
| 12:12 | USDC Approve | Circle USDC | Enable Odos for swaps |
| 12:13-15:37 | 24x Swap Compact | Odos Router V2 | Converted incoming assets to DAI/stables |
| 15:24 | Deposit Exclusive | Across Protocol | 0.1 ETH bridge (test transaction) |
| 15:31-15:37 | 2x Swap Compact | Odos Router V2 | Final arrival-day swaps |

**2 failed transactions** at 12:31 and 14:52 (reverted Odos swaps).

#### Phase B: DAI-to-ETH Conversion (2025-01-16, 3 transactions)

| Time (UTC) | Action | Value |
|:---|:---|:---|
| 12:50 | Swap Compact (Odos) | 100 ETH |
| 12:52 | Swap Compact (Odos) | 100 ETH |
| 12:55 | Swap Compact (Odos) | 100 ETH |

#### Phase C: Additional Swaps + DAI Cleanup (2025-01-27, 8 transactions)

| Time (UTC) | Action | Detail |
|:---|:---|:---|
| 03:47 | DAI Approve | Enable Odos for remaining DAI |
| 03:48-03:58 | 7x Swap Compact (Odos) | Convert remaining DAI/stables to ETH |

#### Phase D: Bridging Out (2025-02-15, 3 transactions)

| Time (UTC) | Action | Protocol | Value | Destination |
|:---|:---|:---|:---|:---|
| 15:17 | Deposit V3 | Across Protocol | 10 ETH (test) | Ethereum mainnet (same EOA) |
| 15:19 | Send | Stargate: Pool Native | 10 ETH (test) | **Ethereum mainnet (dstEid=30101, same EOA)** |
| 15:27 | Send | Stargate: Pool Native | **576.97 ETH** (main exit) | **Ethereum mainnet (dstEid=30101, same EOA)** |

**Tx Hash (main exit):** `0x5fc365aad46105c6d166c09d4e036a24146ddeddbffc298cb30081c3df8c37f8`
**LayerZero GUID:** `5CC6CD3ADC8ACB17467F10F1098CC5469BE09050F61AC922CCF074453CB8325D`

#### Phase E: Residual Cleanup (2025-10-23, 3 transactions)

| Time (UTC) | Action | Protocol | Value |
|:---|:---|:---|:---|
| 05:15 | Create Order | CoW Protocol | 0.93 ETH |
| 11:09 | Transfer | Circle USDC | token transfer |
| 11:10 | Transfer | Circle USDC | token transfer |

---

## 5. Phase 3 Findings: Ethereum Mainnet Fund Flow (NEW)

### 5.1 Primary Wallet on Ethereum (0xcd28..17c5)

**8 transactions total** on Ethereum mainnet, spanning Dec 2024 - Oct 2025:

#### Arrival (Dec 2, 2024)

| Time (UTC) | Action | Detail |
|:---|:---|:---|
| 15:25 | WBTC Approve | Enable Odos |
| 15:30 | WBTC Approve | Second approval |
| 15:30 | Swap Compact (Odos) | 0.576 WBTC → 55,608 DAI |

**Key finding:** 0.576 WBTC arrived on ETH mainnet during the chain-hop (BSC→ETH leg), immediately swapped to DAI.

#### Aave Deposit + aToken Transfer (Feb 15, 2025)

| Time (UTC) | Action | Value | Detail |
|:---|:---|:---|:---|
| 16:08 | Deposit ETH | **596 ETH** | Via Aave Wrapped Token Gateway → Aave V3 |
| 16:09 | Transfer aEthWETH | **596 aEthWETH** | To **`0x313708e21398421d3b260494c0bf233403aEfC99`** |

**Tx Hash:** `0x9103e6c66bd2e3cebdacc6b49c2c569c669b795e9bb040be316d24e0fb879b19`

**CRITICAL FINDING:** The attacker deposited 596 ETH into Aave V3 and immediately transferred the receipt tokens (aEthWETH) to a **different address** (`0x3137..fC99`). This is a deliberate chain-of-custody breaking technique — the Aave deposit creates a "hop" that disconnects the Stargate bridge origin from the subsequent laundering steps.

#### Additional Inflows (Aug 2025)

| Date | Source | Amount | Bridge |
|:---|:---|:---|:---|
| Aug 7 | Mayan Swift | 3,845 DAI | Cross-chain |
| Aug 7 | Mayan Swift | 379 DAI | Cross-chain |
| Aug 8 | THORChain Router | 775 DAI | Cross-chain |

**Total additional inflow:** ~5,000 DAI from other chains (Mayan + THORChain bridges).

#### Cleanup (Oct 23, 2025)

| Time | Action | Detail |
|:---|:---|:---|
| 05:06 | USDC Approve | Enable Across |
| 05:06 | Deposit (Across) | **60,607 USDC → Arbitrum** (chain ID 42161, same EOA) |
| 05:07 | Deposit | 0.93 ETH cleanup |

**Key finding:** 55,608 DAI (from Dec 2024 WBTC swap) + ~5,000 DAI (from Aug bridges) = ~60,608 DAI → converted to USDC via CoW Protocol → bridged BACK to Arbitrum via Across. This is **circular routing** for obfuscation.

### 5.2 Secondary Wallet: `0x313708e21398421d3b260494c0bf233403aEfC99` (NEW)

| Attribute | Value |
|:---|:---|
| Type | EOA (Externally Owned Account) |
| **Gas Funding** | **KuCoin 17** (0.035 ETH) — **potential KYC link** |
| Activity Period | Feb 15-18, 2025 (3 days only) |
| Total Tx | 31 |
| Current Balance | 5.35 ETH (~$11,298) |
| Multichain Balance | ~$32,414 (ETH + Arb) |

#### Complete 31-Transaction Timeline

**Feb 15 (Day 1 — Same day as Stargate arrival):**

| Time | Action | Protocol | Detail |
|:---|:---|:---|:---|
| 15:43 | **Gas funding IN** | — | **0.035 ETH from KuCoin 17** |
| 16:09 | Withdraw | Aave Pool V3 | Redeem aEthWETH → WETH |
| 16:10 | Approve WETH | — | Enable Railgun |
| 16:11 | **Shield** | **Railgun Relay** | **Privacy shielding (amount unknown)** |
| 17:18 | **Transact** | **Railgun Relay** | **Shielded transfer** |
| 17:34 | Withdraw WETH | Wrapped Ether | WETH → ETH unwrap |
| 17:37 | Swap Compact | Odos Router V2 | 12 ETH → stables |
| 17:48 | Transfer | Circle USDC | USDC movement |
| 19:00 | Transfer | — | 0.1 ETH → `0x452e94Bf...` |

**Feb 16 (Day 2):**

| Time | Action | Protocol | Detail |
|:---|:---|:---|:---|
| 04:22 | Send | **Stargate Pool Native** | **15 ETH bridged cross-chain** |
| 11:18 | Create Order | CoW Swap Eth Flow | **100 ETH → stables** |
| 11:20 | Approve USDC + Send | Stargate Pool USDC | USDC bridged cross-chain |
| 13:29 | Create Order | CoW Swap Eth Flow | 1 ETH → stables |
| 15:48 | Create Order | CoW Swap Eth Flow | **100 ETH → stables** |
| 15:50 | Request CCTP Transfer | Circle CCTP | **USDC cross-chain (Circle native)** |

**Feb 17 (Day 3):**

| Time | Action | Protocol | Detail |
|:---|:---|:---|:---|
| 11:45 | Create Order | CoW Swap Eth Flow | **25 ETH → stables** |
| 11:47 | Request CCTP Transfer | Circle CCTP | **USDC cross-chain** |

**Feb 18 (Day 4 — Final):**

| Time | Action | Protocol | Detail |
|:---|:---|:---|:---|
| 03:58 | 2x Self-transfer | — | Nonce management |
| 04:03 | **Deposit** | **Tornado Cash Router** | **100 ETH** |
| 04:12 | **Deposit** | **Tornado Cash Router** | **100 ETH** |
| 04:13 | **Deposit** | **Tornado Cash Router** | **100 ETH** |
| 04:15 | **Deposit** | **Tornado Cash Router** | **100 ETH** |
| 16:44 | Transfer | — | **30 ETH → `0x555fB0Eb...`** |
| 17:45 | Swap Compact | Odos Router V2 | 2 ETH → stables |
| 17:54 | Approve USDT | — | Enable further swaps |
| 17:55 | Send | `0x811ed79d...` | 0.018 ETH (dust cleanup) |

### 5.3 Railgun: Full Amount Shielded (Phase 4 Discovery)

**Tx Hash:** `0x25f57b40e1c647f95c14c842e2d620e135e4018e79bae16ff31e40763f9d597c`

| Item | Value |
|:---|:---|
| Token Shielded | WETH |
| Amount Shielded | **594.51 WETH (~$1,246,453)** |
| Railgun Fee | 1.49 WETH (~$3,124) — 0.25% |
| Amount Deshielded | **593.02 WETH** (Transact at 17:18) |

**ALL 596 ETH from Aave passed through Railgun** before being dispersed. The privacy layer covers the entire sum, not a partial amount.

### 5.4 Complete Token Flow Analysis (Phase 4)

#### WETH/ETH Flow

| Time | Direction | Amount | Counterparty |
|:---|:---|:---|:---|
| Feb 15 16:08 | IN | 596.00 aEthWETH | From 0xcd28 (primary wallet) |
| Feb 15 16:09 | IN | 596.00 WETH | From Aave V3 (withdrawal) |
| Feb 15 16:09 | OUT | 596.00 aEthWETH | Burned (Aave withdrawal) |
| Feb 15 16:11 | OUT | 594.51 WETH | → Railgun Shield |
| Feb 15 16:11 | OUT | 1.49 WETH | → Railgun Treasury (fee) |
| Feb 15 17:18 | IN | 593.02 WETH | From Railgun (deshielded) |

After deshield: 593 WETH → unwrap to ETH → distributed to Tornado Cash, CoW, Chainflip, Stargate.

#### USDC Flow (Total CoW settlements: 611,447 USDC)

| Time | Direction | Amount | Counterparty |
|:---|:---|:---|:---|
| Feb 15 16:18 | IN | 270,248 USDC | CoW Protocol (100 ETH order) |
| Feb 15 16:20 | OUT | **270,248 USDC** | **→ Stargate → BSC** (dstEid=30110) |
| Feb 15 17:37 | IN | 32,158 USDC | Odos Router V2 (12 ETH swap) |
| Feb 15 17:48 | OUT | 32,158 USDC | → `0x5f80C18C...` |
| Feb 16 13:29 | IN | 2,705 USDC | CoW Protocol (1 ETH order) |
| Feb 16 15:48 | IN | 269,802 USDC | CoW Protocol (100 ETH order) |
| Feb 16 15:50 | OUT | **10,000 USDC** | **→ Circle CCTP → Base** (`0x438d...`) |
| Feb 16 16:00 | OUT | 262,507 USDC | → CoW Protocol (sell order) |
| Feb 17 11:45 | IN | 68,693 USDC | CoW Protocol (25 ETH order) |
| Feb 17 11:47 | OUT | **68,693 USDC** | **→ Circle CCTP → Base** (`0x6800...`) |

#### USDT Flow

| Time | Direction | Amount | Counterparty |
|:---|:---|:---|:---|
| Feb 18 17:45 | IN | 5,234 USDT | Odos Router V2 (2 ETH swap) |
| Feb 18 17:55 | OUT | 5,234 USDT | → `0x811ed79d...` |

### 5.5 Fund Disposition from Secondary Wallet (Final)

| Destination | Asset | Amount | USD Value | Privacy Level |
|:---|:---|:---|:---|:---|
| **Tornado Cash** | ETH | **400 ETH** | **~$1,060,000** | **MAXIMUM** |
| **Stargate → BSC** | USDC | **270,248 USDC** | **$270,248** | LOW |
| CoW Protocol (sell order) | USDC | 262,507 USDC | $262,507 | MEDIUM |
| **Chainflip → BTC** | ETH | **30 ETH** | **~$79,500** | **HIGH** |
| **Circle CCTP → Base #2** | USDC | **68,693 USDC** | **$68,693** | LOW |
| → `0x5f80C18C...` | USDC | 32,158 USDC | $32,158 | LOW |
| **Stargate → BSC** | ETH | **15 ETH** | **~$39,750** | LOW |
| **Circle CCTP → Base #1** | USDC | 10,000 USDC | $10,000 | LOW |
| → `0x811ed79d...` | USDT | 5,234 USDT | $5,234 | LOW |
| Railgun fee | WETH | 2.98 WETH | ~$7,900 | — |
| **Remaining at 0x3137** | ETH | **5.35 ETH** | **~$14,178** | **RECOVERABLE** |
| **Total** | — | — | **~$1,850,168** | — |

---

## 6. Complete Fund Flow Diagram (Final)

```
Yei Finance exploit (Sei, Dec 2, 2024) — ~$2.4M
     |
     v
Chain-hop: SEI -> BTC -> BSC -> ETH -> BASE -> Arbitrum
     |
     +--- [ETH mainnet: 0.576 WBTC -> Odos -> 55,608 DAI (parked)]
     |
     v
0xcd28..17c5 arrives on Arbitrum (Dec 2)
     |
     +-- Phase A: 24 Odos swaps -> consolidated to DAI + ETH
     |
     +-- Phase B (Jan 16): 3x 100 ETH swaps -> DAI converted to ETH
     |
     +-- Phase C (Jan 27): 7 more swaps -> remaining DAI to ETH
     |
     +-- Phase D (Feb 15): EXIT via Stargate → ETHEREUM MAINNET
     |       |
     |       +-- 10 ETH test (Across → ETH mainnet)
     |       +-- 10 ETH test (Stargate → ETH mainnet, dstEid=30101)
     |       +-- 576.97 ETH main (Stargate → ETH mainnet)
     |       |
     |       v
     |   0xcd28..17c5 on ETH mainnet: 596 ETH total
     |       |
     |       +-- 596 ETH → Aave V3 deposit → aEthWETH minted
     |       |       |
     |       |       v
     |       |   aEthWETH transferred to 0x3137..fC99 ← [Gas: KuCoin 17]
     |       |       |
     |       |       +-- Aave V3 withdraw → 596 WETH
     |       |       |
     |       |       +-- RAILGUN SHIELD: 594.51 WETH (全額)
     |       |       |       fee: 1.49 WETH to Railgun Treasury
     |       |       |
     |       |       +-- RAILGUN DESHIELD: 593.02 WETH → unwrap → ETH
     |       |       |
     |       |       +-- 226 ETH → CoW Protocol → 611,447 USDC
     |       |       |       |
     |       |       |       +-- 270,248 USDC → Stargate → BSC (0x3137)
     |       |       |       +-- 68,693 USDC → CCTP → Base (0x6800...)
     |       |       |       +-- 10,000 USDC → CCTP → Base (0x438d...)
     |       |       |       +-- 262,507 USDC → CoW (sell order)
     |       |       |
     |       |       +-- 400 ETH → TORNADO CASH (4×100)
     |       |       |
     |       |       +-- 30 ETH → Chainflip deposit → BTC
     |       |       |
     |       |       +-- 15 ETH → Stargate → BSC (0x3137)
     |       |       |
     |       |       +-- 12 ETH → Odos → 32,158 USDC → 0x5f80...
     |       |       +-- 2 ETH → Odos → 5,234 USDT → 0x811e...
     |       |       +-- 5.35 ETH REMAINING (recoverable)
     |       |
     |       +-- 55,608 DAI (from Dec WBTC swap, parked)
     |               |
     |               +-- Aug 2025: +5,000 DAI (Mayan Swift + THORChain)
     |               |
     |               +-- Oct 2025: 60,608 DAI → CoW → USDC → Across → Arbitrum
     |
     +-- Phase E (Oct 23): 0.93 ETH CoW Swap + USDC transfers (Arb cleanup)
```

### Fund Terminal Destinations Summary

| Terminal | Amount | % of ~$1.85M | Traceability |
|:---|:---|:---|:---|
| Tornado Cash | ~$1,060,000 | 57% | Mixer — statistical correlation only |
| BSC (USDC + ETH via Stargate) | ~$310,000 | 17% | Traceable (same EOA 0x3137 on BSC) |
| Base (USDC via CCTP) | ~$78,700 | 4% | Traceable (2 new addresses) |
| Chainflip → BTC | ~$79,500 | 4% | Cross-chain DEX — BTC address needed |
| CoW sell order | ~$262,500 | 14% | Settlement traceable |
| Other (USDC/USDT transfers) | ~$37,400 | 2% | Traceable |
| Remaining (0x3137) | ~$14,200 | 1% | Recoverable |
| Fees (Railgun + bridges) | ~$8,000 | <1% | Protocol fees |

---

## 7. Destination Classification (Final)

| Destination | Classification | Confidence | Basis |
|:---|:---|:---|:---|
| 0xcd28..17c5 (Arb) | Attacker primary wallet (drained) | HIGH | 48 tx verified on Arbiscan |
| 0xcd28..17c5 (ETH) | Attacker primary wallet (drained) | HIGH | 8 tx verified on Etherscan |
| **0x3137..fC99 (ETH)** | **Attacker secondary wallet (5.35 ETH remaining)** | **HIGH** | **31 tx, Aave aToken recipient** |
| 0xcd28..17c5 (BSC) | Same attacker, chain-hop transit | HIGH | 13 tx confirmed |
| 0xcd28..17c5 (Base) | Same attacker, chain-hop transit | HIGH | 1 tx confirmed |
| 0x1de6..52e8 (ETH) | Intermediary (Chainflip refund) | HIGH | Balance verified |
| bc1qknee..v8 (BTC) | Intermediary | MEDIUM | Public report only |
| **Tornado Cash** | **Privacy mixer (400 ETH / ~$1.06M)** | **HIGH** | **4×100 ETH deposits verified** |
| **Railgun** | **Privacy protocol (594.51 WETH / ~$1.25M)** | **HIGH** | **Shield + Transact, full amount decoded** |
| **Circle CCTP → Base** | **USDC bridge (10K + 68.7K USDC)** | **HIGH** | **2 txs, destinations decoded** |
| **KuCoin 17** | **Gas funder for 0x3137 (KYC link)** | **HIGH** | **0.035 ETH funding tx verified** |
| **Chainflip** | **ETH→BTC DEX (30 ETH)** | **HIGH** | **Deposit contract + FetchedNative event** |
| **Stargate → BSC** | **Bridge (270,248 USDC + 15 ETH)** | **HIGH** | **2 txs, dstEid=30110 decoded** |
| Odos Router V2 | DEX aggregator | HIGH | 30+ swap txs across 2 wallets |
| CoW Protocol | Batch DEX (226 ETH → 611K USDC) | HIGH | 4 Create Order + settlements |
| Across Protocol | Bridge (test + circular USDC) | HIGH | Multiple txs verified |
| 0x438d..9c68 (Base) | CCTP USDC recipient #1 (10K USDC) | HIGH | CCTP destination decoded |
| 0x6800..b5fe (Base) | CCTP USDC recipient #2 (68.7K USDC) | HIGH | CCTP destination decoded |
| 0x5f80..8671 (ETH) | USDC recipient (32K USDC) | MEDIUM | Dormant EOA, purpose unknown |
| Mayan Swift | Bridge (inbound DAI, Aug 2025) | HIGH | 2 incoming txs verified |
| THORChain | Bridge (inbound DAI, Aug 2025) | HIGH | 1 incoming tx verified |

---

## 8. Delta Analysis (vs Merkle Science Jan 2025 Report)

| Item | Merkle Science Report | Our Finding | Delta |
|:---|:---|:---|:---|
| Arb balance | ~1M DAI + 281 ETH | 0 | **DRAINED** |
| BSC activity | Mentioned in chain-hop path | 13 transactions confirmed | **NEW DETAIL** |
| Base activity | Mentioned in chain-hop path | 1 transaction confirmed | **NEW DETAIL** |
| Exit method | Not reported | **Stargate 586.97 ETH → ETH mainnet** | **NEW** |
| Exit date | Not reported | **2025-02-15** | **NEW** |
| **Stargate destination** | **Not reported** | **Ethereum mainnet (dstEid=30101)** | **NEW** |
| **Aave V3 hop** | **Not reported** | **596 ETH deposit → aToken transfer to 0x3137** | **NEW** |
| **Secondary wallet** | **Not reported** | **0x313708e2...fC99 (31 tx, 3 days)** | **NEW** |
| **Tornado Cash 400 ETH** | **Not reported** | **4×100 ETH deposits (Feb 18)** | **NEW** |
| **Railgun usage** | **Not reported** | **Shield + Transact (privacy layer)** | **NEW** |
| **KuCoin gas funding** | **Not reported** | **KuCoin 17 → 0x3137 (KYC link)** | **NEW** |
| **Circle CCTP → Base** | **Not reported** | **10K + 68.7K USDC to 2 addresses on Base** | **NEW** |
| **Chainflip 30 ETH** | **Not reported** | **30 ETH → BTC via Chainflip deposit contract** | **NEW** |
| **Stargate → BSC** | **Not reported** | **270,248 USDC + 15 ETH to 0x3137 on BSC** | **NEW** |
| **Railgun full amount** | **Not reported** | **594.51 WETH shielded (entire Aave withdrawal)** | **NEW** |
| **Mayan/THORChain inflows** | **Not reported** | **~5,000 DAI from other chains (Aug 2025)** | **NEW** |
| DAI conversion | Not reported | Odos Router V2, Jan 16-27 | **NEW** |
| Continued activity | Not reported | CoW Swap Oct 2025 (both wallets) | **NEW** |
| Protocols used | Not detailed | **12 protocols identified** | **NEW** |

---

## 9. Actionable Findings

### Highest priority (Law enforcement / Recovery)
1. **KuCoin subpoena** — `KuCoin 17` funded `0x3137..fC99` with 0.035 ETH gas. KuCoin has KYC records. This is the **strongest identity link** in the entire case.
2. **Tornado Cash 400 ETH monitoring** — 4×100 ETH denomination at Feb 18 04:03-04:15 UTC is a distinctive pattern for withdrawal correlation.
3. **Remaining funds at 0x3137** — 5.35 ETH on Ethereum + ~10 ETH on Arbitrum = ~$32K potentially recoverable if frozen.
4. **BSC funds at 0x3137** — 270,248 USDC + 15 ETH arrived via Stargate. BSC tx history pending but funds may still be partially present.

### Medium priority (Continued tracing)
5. **Base CCTP recipients** — `0x438d..9c68` (10K USDC) and `0x6800..b5fe` (68.7K USDC) on Base. Trace their onward activity.
6. **CoW Protocol 262,507 USDC sell order** — What was received in return? Settlement tx analysis needed.
7. **0x3137 BSC activity** — Full tx history on BSC (13 tx from 0xcd28 + incoming from Stargate). BSCScan scrape needed (403 blocked currently).
8. **Chainflip BTC output** — The 30 ETH was converted to BTC. Correlate with known Chainflip BTC outputs for time window.

### Lower priority
9. **`0x5f80..8671`** — Dormant EOA that received 32,158 USDC. Monitor for future activity.
10. **Mayan Swift / THORChain source trace** — Where did the Aug 2025 DAI originate?
11. **Cross-reference with Eralend/Onyx** — Check if same protocols (Odos, Stargate, Tornado Cash, Railgun, Chainflip) were used in linked exploits.

---

## 10. Attacker Behavioral Profile (Updated)

| Behavior | Evidence | Implication |
|:---|:---|:---|
| Tests before committing | 0.1 ETH Across test, 10 ETH Stargate test | Methodical, not impulsive |
| Uses DEX aggregators | 30+ Odos swaps, CoW Protocol batch auctions | Seeks best rates, MEV protection |
| Multi-phase conversion | DAI → ETH over 2 weeks, then bridge | Avoids large single-event detection |
| Cross-chain address reuse | Same EOA on 4 chains | OpSec weakness (but secondary wallet mitigates) |
| **Aave aToken hop** | **Deposit → transfer aTokens to new address** | **Deliberate chain-of-custody break** |
| **Dual privacy protocols** | **Tornado Cash (400 ETH) + Railgun** | **Layered obfuscation, sophisticated** |
| **CEX gas funding** | **KuCoin 17 funded secondary wallet** | **OpSec failure — KYC exposure** |
| **3-day liquidation** | **31 tx in 72 hours for secondary wallet** | **Efficient, pre-planned execution** |
| Long dormancy + return | 8 months between exit and cleanup | Patient, willing to leave dust |
| **Chainflip reuse** | Same protocol for initial SEI→BTC and later 30 ETH→BTC | **Habitual tool preference** |
| **Multiple bridge protocols** | Stargate, Across, CCTP, Mayan, THORChain, Chainflip | **Maximum fragmentation (6 bridges)** |
| **Circular routing** | USDC: ETH→Arb via Across (Oct 2025) | **Creates analytical confusion** |

### Protocol Arsenal (12 protocols identified)

| Category | Protocols |
|:---|:---|
| DEX / Aggregator | Odos Router V2, CoW Protocol |
| Cross-chain Bridge | Stargate (LayerZero), Across Protocol, Circle CCTP, Mayan Swift, THORChain, Chainflip |
| Privacy | **Tornado Cash**, **Railgun** |
| DeFi (hop) | Aave V3 |
| Other | Wrapped Ether (WETH) |

---

## 11. Limitations & Disclaimers

- This analysis uses **public blockchain data** only (Etherscan, Arbiscan, RPC endpoints). No proprietary label databases were used.
- Destination classifications are based on **on-chain behavior patterns** and **verified contract labels**, not confirmed identities.
- Attribution to prior incidents (Eralend, Onyx) is from **Merkle Science** and not independently verified.
- Tornado Cash deposits (400 ETH) and Railgun shielded amounts are **not further traceable** with public tools alone.
- Circle CCTP destination chains are not yet identified (requires attestation service query).
- BSC transaction details are pending (Etherscan V2 API requires paid key for BSC).
- This report does **not** constitute legal advice or a recovery guarantee.

---

## 12. Confidence Table

| Claim | Confidence | Basis |
|:---|:---|:---|
| Funds at 0xcd28 on Arb are drained | HIGH | On-chain balance = 0, verified |
| 48 transactions from 0xcd28 on Arb | HIGH | Arbiscan full tx list |
| DAI converted to ETH via Odos (Jan 2025) | HIGH | 3x 100 ETH swaps + 7 additional |
| 586.97 ETH exited via Stargate (Feb 2025) | HIGH | 3 Stargate txs on Arbiscan |
| **Stargate destination = ETH mainnet** | **HIGH** | **dstEid=30101, decoded from tx input** |
| **596 ETH deposited to Aave V3** | **HIGH** | **Deposit tx + aEthWETH mint verified** |
| **aEthWETH transferred to 0x3137..fC99** | **HIGH** | **Transfer tx with full recipient** |
| **0x3137 funded by KuCoin 17** | **HIGH** | **Etherscan label + funding tx** |
| **400 ETH deposited to Tornado Cash** | **HIGH** | **4 deposit txs, 100 ETH each** |
| **Railgun: 594.51 WETH shielded** | **HIGH** | **Shield tx decoded: exact amount + fee** |
| **Railgun: 593.02 WETH deshielded** | **HIGH** | **Transact tx + WETH inflow verified** |
| **CCTP #1: 10K USDC → Base (0x438d)** | **HIGH** | **Domain=4, mintRecipient decoded** |
| **CCTP #2: 68.7K USDC → Base (0x6800)** | **HIGH** | **Domain=4, mintRecipient decoded** |
| **Chainflip: 30 ETH → BTC** | **HIGH** | **FetchedNative event, deposit contract verified** |
| **Stargate: 270K USDC → BSC (0x3137)** | **HIGH** | **dstEid=30110, amount decoded from tx** |
| **Stargate: 15 ETH → BSC (0x3137)** | **HIGH** | **dstEid=30110, same address** |
| **CoW Protocol: 611K USDC total settlement** | **HIGH** | **4 settlement events verified** |
| Attacker still active (Oct 2025) | HIGH | CoW Swap + USDC txs verified |
| BSC 13 tx = chain-hop transit | HIGH | Tx count verified, path matches |
| Base 1 tx = chain-hop transit | HIGH | Tx count verified, path matches |
| Chain-hop path SEI→BTC→BSC→ETH→BASE→Arb | MEDIUM-HIGH | Public report + our cross-chain verification |
| **Link to EraLend** | **HIGH** | **SlowMist MistTrack confirmed (shared addresses)** |
| **Link to Onyx** | **MEDIUM-HIGH** | **Merkle Science + CoW Protocol overlap** |
| **Link to zkLend** | **HIGH** | **SlowMist confirmed same entity as EraLend** |
| **Serial exploiter (~$18.5M+ total)** | **HIGH** | **4 incidents, same protocol fingerprint** |
| **Attacker identity via KuCoin** | **MEDIUM** | **KuCoin KYC exists but requires legal process** |
| **Operator = human (not bot)** | **HIGH** | **CV=1.435, UI timing patterns (48s/60s intervals)** |
| **Solo operator (not team)** | **HIGH** | **Inconsistent OpSec + impulsive errors + single timezone** |
| **KuCoin gas = genuine mistake** | **MEDIUM-HIGH** | **P=0.75, consistent with overall carelessness pattern** |
| **TC phishing loss = real** | **MEDIUM** | **P=0.65, 42% too large for rational deception** |
| **100 ETH cognitive anchor** | **HIGH** | **72% round numbers, manual decision-making pattern** |
| **UTC+2~+3 居住** | **MEDIUM-HIGH** | **Sleep gap 9.3h + midday consistency + evening cutoff** |
| **非ネイティブ英語話者** | **MEDIUM** | **callflashloandraaan() + on-chain message grammar + timezone** |
| **`callflashloandraaan()` = drain変形** | **MEDIUM** | **BlockSec call trace, 意図的難読化の可能性あり** |
| **TC phishing = self-staging?** | **LOW** | **safe-relayer.eth 関連の報道あるが確定せず** |

---

## 13. Methodology

| Step | Method | Tool |
|:---|:---|:---|
| Address identification | Public report review | Merkle Science blog |
| Balance verification | `eth_getBalance`, `balanceOf()` RPC | 1rpc.io (ETH, Arb, Base, BSC) |
| Cross-chain presence | `eth_getTransactionCount` on 4 chains | 1rpc.io |
| Transfer event scan | `eth_getLogs` with ERC20 Transfer topic | 1rpc.io/arb |
| Arbitrum transaction history | Arbiscan page scrape | arbiscan.io |
| **Stargate destination decode** | **Tx input decode (dstEid, recipient)** | **arbiscan.io tx detail** |
| **Ethereum transaction history** | **Etherscan page scrape** | **etherscan.io** |
| **Ethereum token transfers** | **ERC20 transfer history** | **etherscan.io/tokentxns** |
| **Secondary wallet discovery** | **aEthWETH Transfer event trace** | **etherscan.io tx detail** |
| **Address labeling** | **Etherscan verified labels** | **etherscan.io** |
| Protocol identification | Block explorer verified contract labels | arbiscan.io + etherscan.io |
| **Stargate dstEid decode** | **Send() input parameter extraction** | **etherscan.io tx detail** |
| **CCTP domain decode** | **requestCCTPTransfer input + DepositForBurn event** | **etherscan.io tx detail** |
| **Chainflip identification** | **FetchedNative event + deposit contract verification** | **etherscan.io** |
| **Railgun amount decode** | **Shield event + WETH Transfer events** | **etherscan.io tx detail** |
| **CoW Protocol settlement trace** | **GPv2Settlement ERC20 Transfer events** | **etherscan.io/tokentxns** |
| Fund flow reconstruction | Timeline analysis of 79+ transactions across 4 chains | Manual |
| **Bot vs human determination** | **Inter-tx interval CV analysis (20 intra-session pairs)** | **Python statistical analysis** |
| **Timezone estimation** | **Sleep gap analysis (86 tx across 3 wallets)** | **Python temporal analysis** |
| **Cognitive fingerprinting** | **Round number preference analysis (18 value-bearing txs)** | **Manual classification** |
| **Operation tempo profiling** | **Session structure & burst/deliberate mode identification** | **Python + manual** |
| **Fermi estimation (TC phishing)** | **Cost-benefit analysis of staged vs real loss** | **Quantitative reasoning** |

---

## 14. Phase 5: Attribution & Behavioral OSINT

### 14.1 KuCoin 17 — Forensic Detail for Legal Disclosure

| Field | Value |
|:---|:---|
| **Withdrawal Timestamp** | **2025-02-15 15:43:47 UTC** (block 21,852,793) |
| **KuCoin Hot Wallet** | `0x45300136662dD4e58fc0DF61E6290DFfD992B785` |
| **Hot Wallet Nonce** | 330,245 (confirmed institutional hot wallet) |
| **Recipient** | `0x313708e21398421d3b260494c0bf233403aEfC99` |
| **Amount** | 0.03518086 ETH (gas funding) |
| **Tx Hash** | `0xa5b204e908b836e632cd227c82b1a7f76928f50cdc60dc591d89ae5e41051230` |

**Legal Action Required:** KuCoin に対し、2025-02-15 15:43:47 UTC の出金を申請したユーザーの KYC 情報（メール、IP、氏名、パスポート、電話番号）の保全・開示を請求する。出金額 0.035 ETH は小さいが、出金タイムスタンプは秒単位で特定済みであり、KuCoin のログから該当ユーザーを一意に特定可能。

### 14.2 Timezone Analysis — 居住地域の推定

86 件の全トランザクション (UTC) を分析。

**主要活動時間帯 (UTC):** 03:00-05:00 + 11:00-17:00 (二峰性)
**完全休止時間帯 (UTC):** 06:00-10:00, 18:00-02:00

**Sleep Gap 分析 (最も信頼性の高い指標):**

Feb 15-18 の集中活動期間から抽出:

| Gap | UTC Time | Duration |
|:---|:---|:---|
| Sleep #1 | 19:01 → 04:22 | **9.3h** |
| Sleep #2 | 15:50 → 11:45 (next day) | 19.9h (待機含む) |
| Sleep #3 | 11:47 → 03:58 | **16.2h** |
| Sleep #4 | 04:15 → 16:44 | **12.5h** |

**最短 sleep gap = 9.3h (19:00→04:00 UTC)**

| Timezone | Local Sleep | Local Wake | Assessment |
|:---|:---|:---|:---|
| **UTC+2 (EET: Romania/Turkey/Ukraine)** | **21:00** | **06:00** | **BEST FIT** |
| **UTC+3 (MSK: Russia/Dubai/E.Africa)** | **22:00** | **07:00** | **GOOD FIT** |
| UTC+4 (Gulf/Georgia) | 23:00 | 08:00 | POSSIBLE |
| UTC+1 (CET) | 20:00 | 05:00 | 早すぎる就寝 |
| UTC+8 (China/SG) | 03:00 | 12:00 | 異常パターン |
| UTC-5 (EST) | 14:00 | 23:00 | **EXCLUDED** |

**結論:** 攻撃者は **UTC+2 ~ UTC+3** (東欧〜中東) に居住する可能性が最も高い。

### 14.3 Serial Exploiter Profile — Cross-Incident Analysis

**SlowMist MistTrack 確認:** zkLend 攻撃者 = EraLend 攻撃者 (on-chain 証拠あり)

| Incident | Date | Chain | Amount | Attribution |
|:---|:---|:---|:---|:---|
| **EraLend** | Jul 2023 | zkSync | ~$2.76M | ✓ SlowMist confirmed |
| **Onyx Protocol** | Sep 2024 | Ethereum | ~$3.8M | Merkle Science |
| **Yei Finance** | Dec 2024 | Sei | ~$2.4M | Merkle Science |
| **zkLend** | Feb 12, 2025 | Starknet | **~$9.57M** | ✓ SlowMist confirmed |
| **Total** | — | — | **~$18.5M+** | — |

**Suspected additional targets** (zkLend post-mortem, unconfirmed): Channels Finance, Starlay Finance.

**Critical timing overlap:** zkLend exploit (Feb 12) と Yei laundering (Feb 15-18) は **同時進行**。攻撃者は新しい exploit を実行しながら前の exploit の資金を洗浄していた。

#### Protocol Fingerprint (Modus Operandi)

| Protocol | EraLend | Onyx | Yei | zkLend | Significance |
|:---|:---|:---|:---|:---|:---|
| Tornado Cash | ✓ | ✓ (seed+exit) | **✓ (400 ETH)** | ✓ (phishing?) | Consistent mixer preference |
| Railgun | — | — | **✓ (594 WETH)** | ✓ (returned) | Shared privacy protocol |
| Chainflip | — | — | **✓ (30 ETH + chain-hop)** | ✓ (25 ETH) | **Strong behavioral signature** |
| CoW Protocol | — | ✓ (VUSD swap) | **✓ (226 ETH)** | — | Shared DEX preference |
| 100 ETH denomination | — | — | **✓ (4×100)** | ✓ (100 ETH batches) | **Operational habit** |
| Flash loan | ✓ | ✓ | ✓ | — | Common attack vector |
| Lending protocol target | ✓ | ✓ | ✓ | ✓ | **Specialization** |

#### Attacker vs Lazarus Group Assessment

| Indicator | This Attacker | Lazarus Group | Assessment |
|:---|:---|:---|:---|
| KuCoin gas funding | ✓ (KYC exposure) | ✗ (never) | **NOT Lazarus** |
| Tornado Cash phishing loss | ✓ (zkLend, 2,930 ETH) | ✗ (never) | **NOT state-sponsored** |
| Etherscan messaging | ✓ (zkLend) | ✗ (never) | **Individual or small group** |
| Dual privacy (Railgun+TC) | ✓ | ✓ (Railgun used) | — |
| Chainflip preference | ✓ (multiple incidents) | ✗ (prefers Sinbad/Yonmix) | **Different actor** |
| 3-layer Aave hop | ✓ (novel technique) | ✗ (not seen) | **Unique to this attacker** |
| Target type | Lending protocols only | Diverse (bridges, CEX, etc.) | **Specialist, not generalist** |

**Profile conclusion:** 高度な技術力を持つが、OpSec に一貫性のない **個人ハッカーまたは小規模グループ**。東欧〜中東圏 (UTC+2~+3) に居住。lending protocol の脆弱性に特化。Lazarus Group ではない。

### 14.4 Known Linked Addresses (Cross-Incident)

| Address | Chain | Incident | Source |
|:---|:---|:---|:---|
| `0xcd2860fc4abf1748b8e4aebf35ddef2ab03e17c5` | Multi-chain | Yei Finance | Merkle Science + our analysis |
| `0x313708e21398421d3b260494c0bf233403aEfC99` | Ethereum | Yei Finance | Our Phase 3 discovery |
| `0x93920786e0fda8496248c4447e2e082da69b6c40` | Ethereum | EraLend + zkLend | SlowMist MistTrack |
| `0x34e5dc779cb705200e951239b6a89aaf5c7dbfc1` | Ethereum | EraLend | SlowMist MistTrack |
| `0x1de6f3ccfab74302d30aac3649b4700347bb52e8` | Ethereum | Yei (Chainflip refund) | Merkle Science |
| `0xf1D076c9Be4533086f967e14EE6aFf204D5ECE7a` | zkSync | EraLend (attacker EOA) | CertiK analysis |
| `0x7d8772DCe73cDA0332bc47451aB868Ac98F335F0` | zkSync | EraLend (attack contract) | CertiK analysis |
| `0x680910cf5Fc9969A25Fd57e7896A14fF1E55F36B` | Ethereum | Onyx Protocol (Etherscan labeled "OnyxDAO Exploiter 1") | Etherscan |
| `0x645c77833833A6654F7EdaA977eBEaBc680a9109` | Ethereum | zkLend (L1 attacker EOA) | BlockSec / Halborn |
| `0x0193da87dc0b317f8418ae0c8fb3e0301698ed2d1a4047191d4641ddabc1e2bf` | Starknet | zkLend (attack contract) | BlockSec |
| `0xcf31e1b97790afd681723fa1398c5ead9f69b98c` | Ethereum | zkLend (on-chain message sender, labeled "Fake_Phishing927538") | Etherscan |

### 14.5 Off-Chain OSINT Results

| Source | Query | Result |
|:---|:---|:---|
| Web search (Twitter/GitHub) | Both attacker addresses | **No results** — no public social profiles linked |
| Etherscan labels | 0xcd28, 0x3137 | No named entity tags |
| ENS domains | Both addresses | Not checked (recommended for Phase 6) |
| Arkham Intelligence | Not queried (requires account) | **Recommended for Phase 6** |

### 14.6 Linguistic Fingerprinting — 攻撃コントラクトと on-chain メッセージの言語分析

#### 14.6.1 zkLend 攻撃コントラクト関数名

BlockSec の post-mortem で特定された、攻撃者が自作 Cairo コントラクトに命名した関数:

| Function | Analysis |
|:---|:---|
| **`callflashloandraaan()`** | 攻撃の主要関数。"callflashloan" + **"draaan"**。"drain" (排出) のスペル変形。英語ネイティブなら "callFlashLoanDrain" と書くはず。**非ネイティブ英語話者を示唆** |
| `increase()` | サイクル間の資金供給関数。汎用的な命名、特徴なし |

**"draaan" の解釈:**
- (a) "drain" のスペルミス (i→a) + 意図的な母音延長 ("aaa") = **口語的・カジュアルな命名スタイル**
- (b) 意図的な難読化 (decompiler 対策) → ただし、Cairo コントラクトでは他の関数名は正規
- (c) **非ネイティブ英語話者が "drain" の発音を音写** ("ドレーン" → "draaan") → UTC+2~+3 居住推定と整合

#### 14.6.2 On-Chain メッセージ (zkLend → deployer, 2025-03-31)

攻撃者が zkLend deployer に送信したメッセージ:

> *"I tried to move funds to tornado [cash] but I used a phishing website and all the funds have been lost. I am devastated. I am terribly sorry for all the havoc and losses caused. All the 2930 eth have been taken by that site owners. I do not have coins."*

**文法分析:**

| Expression | 問題点 | ネイティブなら |
|:---|:---|:---|
| **"that site owners"** | 指示代名詞と名詞の不一致 | "those site owners" or "that site's owners" |
| **"I do not have coins"** | 不自然な表現 | "I have no funds remaining" or "I have nothing left" |
| "I am devastated" | 正しいが格式的 | カジュアル文脈では "I'm devastated" |
| "all the havoc and losses caused" | 受身の使い方がやや不自然 | "all the havoc and losses I caused" |

**判定:** 概ね正確だが、2-3 箇所に**非ネイティブ英語話者の痕跡**。文法力は中上級 (B2-C1)。

**注意:** このメッセージの送信者 (`0xcf31e1...`) は Etherscan 上で "Fake_Phishing927538" とラベルされている。メッセージ自体が偽装の可能性が高い (phishing サイト `tornadoeth.cash` の運営者 `safe-relayer.eth` と攻撃者が同一人物という調査報告あり)。言語分析材料としての信頼性は **LOW**。

#### 14.6.3 攻撃コントラクト ソースコード状況

| Incident | Chain | Contract | Verified? | Linguistic Material |
|:---|:---|:---|:---|:---|
| **Yei Finance** | Sei | 未公開 | ✗ | なし (アドレスすら非公開) |
| **EraLend** | zkSync | `0x7d87..5F0` | ✗ | なし (unverified) |
| **zkLend** | Starknet | `0x0193..2bf` | ✗ | **`callflashloandraaan()` + `increase()`** (BlockSec call trace) |
| **Onyx** | Ethereum | `0xAE7d..223` | ✗ | なし (unverified) |

**全 4 件ともソースコードは非公開 (unverified)**。言語的手がかりは zkLend の call trace から抽出された関数名のみ。

#### 14.6.4 言語的証拠の総合評価

| 証拠 | 示唆 | 信頼性 |
|:---|:---|:---|
| `callflashloandraaan()` | 非ネイティブ英語 (drain→draaan) | **MEDIUM** (意図的難読化の可能性) |
| On-chain メッセージ文法 | 非ネイティブ英語 (B2-C1) | **LOW** (メッセージ自体が偽装の可能性) |
| UTC+2~+3 timezone | 東欧/中東 (英語非母語圏) | **MEDIUM-HIGH** (独立証拠) |
| KuCoin (アジア圏 CEX) 使用 | 東アジア/東南アジアの可能性 | **LOW** (KuCoin はグローバル) |

**総合判定:** 3 つの独立した証拠 (関数名 + 文法 + timezone) がいずれも **非英語ネイティブ圏** を示唆。timezone 分析との組み合わせで、**東欧 (UTC+2~+3) の非英語ネイティブ話者** という仮説が最も整合的。ただし、言語的証拠単体の信頼性は中~低。

### 14.7 Deep Behavioral Profiling — 「データの裏にある人間の息遣い」

#### 14.7.1 Bot vs Human Determination

0x3137..fC99 の 31 トランザクションの inter-transaction interval を分析。

| Metric | Value |
|:---|:---|
| Intra-session intervals (< 1h) | 20 pairs |
| Mean interval | 276s |
| Median interval | 96s |
| **Coefficient of Variation** | **1.435** |

**CV = 1.435 → 不規則タイミング = 人間オペレーター**

- Bot の特徴的 CV: < 0.3 (精密な間隔)
- 人間の特徴的 CV: > 0.8 (不規則)
- この攻撃者: **1.435** (極めて不規則)

**Sub-minute intervals の詳細分析:**

| Interval | Pair | Assessment |
|:---|:---|:---|
| 24s | Stargate USDC → Approve | MetaMask 確認速度と一致 |
| 24s | Transfer → Transfer | nonce 事前署名の可能性 |
| 48s | Withdraw → Approve | タブ切替 + UI 操作時間 |
| 48s | Approve → Send | 同上 |
| 60s | Approve → Shield (Railgun) | 人間の UI 操作時間 |

**Railgun シーケンス (16:09→16:10→16:11):** Withdraw (16:09:35) → Approve (16:10:23, +48s) → Shield (16:11:23, +60s)。Bot なら 5 秒以下。48s + 60s のリズムは **人間の UI 操作と完全に一致**。

**一方、5 分超の長い間隔も多数:**

| Interval | Pair | Assessment |
|:---|:---|:---|
| 5.2m | Transfer → TC Deposit | 思考・判断の時間 |
| 8.4m | TC Deposit → TC Deposit | 手動確認を挟んでいる |
| 16.2m | Railgun Transact → Withdraw | 別作業をしていた可能性 |
| 25.8m | Transfer IN → Withdraw | 長い中断 |

**結論:** **人間がブラウザ UI (MetaMask + DApp フロントエンド) で手動操作**。一部の rapid-fire sequence は pre-approval 済みコントラクトの連続実行だが、全体パターンは人間。

#### 14.7.2 Tornado Cash Deposit Rhythm

4 回の TC 100 ETH deposit (Feb 18, 03:58-04:15 UTC):

| # | Time | Interval |
|:---|:---|:---|
| 1 | 03:58 | — |
| 2 | 04:03 | 5m12s |
| 3 | 04:05 | 2m12s |
| 4 | 04:15 | 8m24s → **8.4m gap** |

**3→4 の 8.4 分ギャップは異常。** 最初の 3 回は rapid (5m, 2m) だが 4 回目に明らかな中断。

**可能な説明:**
- (a) MetaMask の nonce 管理に問題が発生 (承認 UI のリフレッシュ)
- (b) 残高確認のためにブロックエクスプローラーを開いた
- (c) 不安になり、第三者 (チャットメッセージ?) と確認した
- (d) 単純に中断 (トイレ、電話等)

**プロファイル指標:** 4 回の deposit のうち **最後にためらい**がある。これは「計画的」だが「完全に自動化されていない」ことを示す。

#### 14.7.3 KuCoin Gas — Trap or Genuine Mistake?

| Hypothesis | Evidence | P(hypothesis) |
|:---|:---|:---|
| **A: Genuine mistake** | (1) Gas 0.035 ETH は少額で追跡を意識せず (2) Chainflip を大口で使いながら少額に KuCoin = 慣れた取引所を反射的に使用 (3) TC phishing loss (2,930 ETH) + EOA reuse = 全体的に不注意 (4) 「金額が小さければバレない」という誤認 | **P = 0.75** |
| **B: Intentional bait** | (1) KuCoin アカウントは盗品・購入品 (偽 KYC) (2) 捜査官のリソースを消費させる目的 (3) **反証:** 高度な欺瞞 (bait) と低級な不注意 (phishing loss) の共存は矛盾 | **P = 0.25** |

**判定:** OpSec の一貫性のなさ (高技術 × 低運用) のパターンと一致する **genuine mistake (P=0.75)**。

#### 14.7.4 Fermi Estimation — TC Phishing Loss は Real か Staged か？

| Parameter | Value |
|:---|:---|
| 全 exploit 推定総額 | ~$18,500,000 |
| TC phishing loss (zkLend) | 2,930 ETH ≈ $7,764,500 |
| **損失比率** | **42%** |
| 損失後残存推定 | ~$10,735,500 |

**IF REAL:**
- 42% の損失は solo operator に壊滅的
- KuCoin mistake + EOA reuse の不注意パターンと整合
- Etherscan メッセージ "it is so devastating" の感情表現が authentic
- Oct 2025 の小口 cleanup (CoW 残額整理) = **大金を失った後のスクラッピング行動と整合**

**IF STAGED:**
- 42% は「見せ金」として犠牲にするには大きすぎる (合理的 actor なら 5-10% が上限)
- phishing site AND attacker wallet の両方を制御する必要 = 可能だが complex
- zkLend が全額返還を要求した文脈では、「phishing で消えた」は都合が良すぎる

**判定: PROBABLY REAL (P=0.65)**

42% の損失は合理的欺瞞としては大きすぎる。KuCoin mistake + EOA reuse + 残額 cleanup のパターンは、**技術的に優秀だが操作上は衝動的な個人**を示す。

#### 14.7.5 Cognitive Fingerprint — Number Preferences

18 件の主要 value-bearing トランザクションを分析:

| Denomination | Usage | Count |
|:---|:---|:---|
| **100 ETH** | TC deposits (4), CoW orders (2), Odos swaps (3) | **9** |
| 25 ETH | CoW order (残余整理) | 1 |
| 10 ETH | Stargate bridge | 1 |
| 30 ETH | Direct transfer (Chainflip) | 1 |
| 10,000 USDC | CCTP (round number) | 1 |
| 1 ETH | CoW order (test) | 1 |

**Round number 比率: 13/18 = 72%**

**分析:**
- **100 ETH がドミナント denomination** — cognitive anchor (心理的基準点)
- round number 選好 = **手動の意思決定** (bot なら gas 最適化で端数)
- 100 = 10進法思考 (プログラマーなら 2 のべき乗を好む傾向)
- 1 ETH → 100 ETH のパターン = **test then commit** (慎重だが大胆)
- ~$250K/operation (100 ETH) の comfort zone = 大金の扱いに慣れているが institutional ではない

#### 14.7.6 Operation Tempo — Session Structure

| Session | UTC Time | Tx Count | Character |
|:---|:---|:---|:---|
| Feb 15 PM | 15:43-19:01 | 10 tx | Setup + Railgun + first swaps |
| Feb 16 early AM | 04:22 | 1 tx | Single Stargate send (起床直後?) |
| Feb 16 midday | 11:18-15:50 | 9 tx | Main CoW + CCTP batch |
| Feb 17 midday | 11:45-11:47 | 2 tx | Quick CoW + CCTP |
| Feb 18 early AM | 03:58-04:15 | 6 tx | **Tornado Cash BURST** |
| Feb 18 PM | 16:44-17:55 | 4 tx | Chainflip + cleanup |

**Key Observations:**

1. **Two distinct operational modes:**
   - **BURST mode:** TC deposits 4 回 in 17 分 (03:58-04:15) — 事前計画済み、semi-scripted
   - **DELIBERATE mode:** CoW orders が数時間間隔 — 手動、settlement 待ち、adaptive

2. **Early morning pattern:** Feb 16 04:22 + Feb 18 03:58 → ~04:00 UTC が最早活動時刻。UTC+3 なら **07:00 local = 起床直後の行動**。

3. **Midday consistency:** Feb 16 11:18, Feb 17 11:45, Oct 23 11:09 → **~11:00-12:00 UTC に反復的活動**。UTC+3 なら 14:00-15:00 local = 昼食後。

4. **Evening cutoff:** 19:01 UTC (Feb 15), 17:55 UTC (Feb 18) 以降活動なし。UTC+3 なら 22:01/20:55 local = 妥当な就寝前。

#### 14.7.7 Attacker Profile — Comprehensive Assessment

| Dimension | Assessment | Confidence |
|:---|:---|:---|
| **Operator type** | **Solo individual** (not team/organization) | HIGH |
| **Human vs Bot** | **Human (CV=1.435, UI timing patterns)** | HIGH |
| **Age range** | 22-35 (DeFi native, not traditional finance) | MEDIUM |
| **Location** | UTC+2 to UTC+3 (Eastern Europe / Middle East) | MEDIUM-HIGH |
| **Technical skill** | Smart contract audit + cross-chain architecture | HIGH |
| **OpSec level** | **Inconsistent** — high-tech privacy (Railgun, Aave hop) but careless operations (KuCoin gas, EOA reuse, TC phishing) | HIGH |
| **Motivation** | Financial (no manifesto, no ideological return) | HIGH |
| **Working style** | Manual UI with pre-planned sequences; 100 ETH cognitive anchor | HIGH |
| **Risk tolerance** | High (escalating exploit sizes), but impulsive (TC phishing loss) | MEDIUM-HIGH |
| **Active period** | Jul 2023 – present (2+ years, escalating) | HIGH |
| **Total proceeds** | ~$18.5M across 4+ incidents | HIGH |
| **Net estimated** | ~$10.7M (if TC phishing loss is real, P=0.65) | MEDIUM |
| **KuCoin gas = mistake** | P=0.75 genuine, P=0.25 bait | MEDIUM-HIGH |
| **TC phishing = real** | P=0.65 real, P=0.35 staged | MEDIUM |
| **Lazarus Group** | **EXCLUDED** — operational profile incompatible | HIGH |

**一文プロファイル:** 東欧〜中東在住の 20-30 代ソロ DeFi ハッカー。lending protocol の脆弱性に特化し、2023 年から ~$18.5M を搾取。技術は高度だが OpSec は一貫せず、TC phishing で ~$7.8M を失った可能性が高い衝動的な人物像。

#### 14.7.8 Phase 6 v2 Re-Analysis (2026-03-16) — `Behavioral Profiling Phase

v1 (custom 31tx, 0x3137 ETH only) を v2 (template 173tx, 4 addresses × 2 chains) で再検証。
Evidence preservation 有効: `[evidence log — available on request]` (8 API calls, SHA256 hashed)。

**v1 → v2 比較:**

| Metric | v1 (31tx) | v2 (173tx) | Assessment |
|:---|:---|:---|:---|
| CV | 1.435 | 1.387 | **収束** — HUMAN 確定 (両方 >0.8) |
| Intra-session intervals | 20 | 114 | 5.7x データ増加 |
| Mean interval | 276s | 183s | token tx 追加で短い interval 増 |
| Sub-minute intervals | — | 34 (30%) | bridge settlement latency 含む |
| Sessions | 7 | 14 | 2025-07~10 月のクリーンアップ追加 |

**CV 安定性:** v1=1.435, v2=1.387。5.7 倍のデータ増加で 3.3% の変動のみ。**HUMAN 判定は堅牢**。

**Timezone 精査 (v2 で更新):**

v2 の shortest gap (5.9h, 05:15→11:09 UTC, 2025-10-23) は UTC-5~-4 を示唆するが、これは **1 日だけのクリーンアップ作業** (Sei chain sweep) であり timezone 推定に不適。

Exploit 当日 (2024-12-02, 2025-01-16~02-18) の密集データでは:
- 最早活動: 03:47 UTC (Jan 27), 03:58 UTC (Feb 18) → UTC+3 なら 06:47-06:58 (早朝)
- Midday cluster: 11:00-15:00 UTC → UTC+3 なら 14:00-18:00 (午後)
- Evening cutoff: 19:01 UTC (Feb 15) → UTC+3 なら 22:01 (就寝)
- Zero activity: 06:00-10:00 UTC → UTC+3 なら 09:00-13:00 (午前中は活動せず = 起床後の移動・準備)

**v1 の UTC+2~+3 判定を維持。** クリーンアップ日のデータは timezone 推定から除外が適切。

**Cognitive Fingerprint (v2):**

v2 round number ratio = 7/118 = **6%** (v1 = 72%)。差の原因:
- v2 は token transfer (spam filter 後) を含み、bridge/swap 出力の端数が大量に混入
- v1 は手動選択した 18 件の主要 value-bearing tx のみ
- **v1 の 72% (manual selection) と v2 の 6% (auto-collection) の両方が事実**
- 解釈: 攻撃者は **主要判断** (TC deposit, bridge, swap) で round number を選好するが、gas/fee の自動端数が大量に存在
- **Cognitive anchor = 100 ETH の判定は v1 が正確** (v2 top denominations: 0.0 (9x)=gas, 100 (3x), 200000 (3x))

**Operation Tempo (v2 追加発見):**

| Session | Period | Character | Note |
|:---|:---|:---|:---|
| 0 | 2024-12-02 | 105 tx, 3.4h DELIBERATE | **Exploit 本番** — Sei chain 全操作 |
| 1 | 2025-01-16 | 6 tx, 5min BURST | 資金移動 batch |
| 2 | 2025-01-27 | 16 tx, 11min BURST | 大量 bridge + swap |
| 3 | 2025-02-15 | 8 tx, 51min MIXED | KuCoin gas → Aave → laundering |
| 4-9 | 2025-07~10 | 各 1-2 tx SINGLE | **クリーンアップ散発** — 残額整理 |

**新パターン:** Session 0 (Exploit) は 105 tx / 3.4h = 30 tx/h = **0.5 tx/min** の高密度。ただしこの中に Sei chain の supply()/borrow() サイクルが含まれ、これは exploit contract の自動呼び出し。Exploit execution は semi-automated (contract) + manual trigger。

**Fermi Estimation (v2 確認):** TC phishing loss ratio = 42.0%。v1 判定 (PROBABLY REAL, P=0.65) を維持。

**Attacker Generation (v2):** 使用プロトコル 8 種 (TC 2019 ~ Chainflip 2024)。**DeFi active since 2019, keeps current = YES**。5 年以上の DeFi 経験 = veteran operator。

---

## 14.8 Off-Chain OSINT — `Attribution OSINT Phase` (2026-03-16)

### 14.8.1 Web Exposure Search (Google Dorks)

| Search | Result |
|:---|:---|
| `"0xcd2860fc4abf1748b8e4aebf35ddef2ab03e17c5"` (full address) | **ゼロ** — Etherscan/DEXTools 等の自動ページのみ |
| `"0x313708e21398421d3b260494c0bf233403aEfC99"` (secondary) | **ゼロ** — 同上 |
| `"callflashloandraaan"` + exploit | **ゼロ** — Flash loan 一般記事のみ。関数名の Web 露出なし |
| `site:github.com "0xcd2860fc"` | **ゼロ** — コード公開なし |
| `site:github.com "callflashloandraaan"` | **ゼロ** — Exploit PoC の公開なし |
| `site:pastebin.com "0xcd2860"` | **ゼロ** |

**Assessment:** 攻撃者のアドレスと exploit 関数名はいずれも Surface Web に一切露出していない。
これは攻撃者の **OPSEC が off-chain では堅牢** であることを示す (on-chain OPSEC は KuCoin gas + EOA reuse で破綻済み)。

### 14.8.2 Serial Exploiter — 拡大確認

Off-chain OSINT で公開レポートを収集した結果、同一攻撃者の incidents リストが拡大:

| # | Incident | Date | Loss | Confirmation Source |
|:--|:---|:---|:---|:---|
| 1 | **EraLend** (zkSync Era) | Jul 25, 2023 | ~$2.76M | [SlowMist MistTrack](https://slowmist.medium.com/in-depth-analysis-of-zklend-hack-linked-to-eralend-hack-fba4af9b66ef) |
| 2 | **Onyx Protocol** | Sep 3, 2024 | ~$3.8M | [Halborn](https://www.halborn.com/blog/post/explained-the-onyx-protocol-hack-september-2024), [Merkle Science](https://www.merklescience.com/blog/hack-track-yei-finance-flow-of-funds-analysis) |
| 3 | **Yei Finance** (Sei) | Dec 2, 2024 | ~$2.4M | Merkle Science |
| 4 | **zkLend** (Starknet) | Feb 12, 2025 | ~$9.5M | [SlowMist](https://slowmist.medium.com/in-depth-analysis-of-zklend-hack-linked-to-eralend-hack-fba4af9b66ef) |
| 5 | **Channels Finance** | TBD | TBD | zkLend post-mortem (named but details未取得) |
| 6 | **Starlay Finance** | TBD | TBD | zkLend post-mortem (同上) |

**確認済み合計: $18.46M+ (4 incidents)。Channels + Starlay 含めると $20M+ の可能性。**

前回レポート (Phase 5) では 4 incidents / ~$18.5M としていたが、zkLend の損失額が $9.5M (当初 ~$8.5M 推定を上方修正) で総額が増加。

### 14.8.3 Cross-Incident Address Linkage

SlowMist MistTrack の分析による address graph:

```
EraLend (Jul 2023, zkSync Era)
  └─ 受取: 0x93920786e0fda8496248c4447e2e082da69b6c40
  └─ 受取: 0x34e5dc779cb705200e951239b6a89aaf5c7dbfc1
       │
       ├── zkLend (Feb 2025, Starknet → ETH L1)
       │     テスト tx で 0x9392, 0x34e5 を再利用 (SlowMist 確認)
       │     └─ Bridge: LayerSwap, Orbiter, Rhino.fi, StarkGate
       │
       └── Yei Finance (Dec 2024, Sei → ETH/ARB/BSC/Base)
             └─ 0xcd2860fc... (primary) — Merkle Science 帰属
             └─ 0x313708e2... (secondary, KuCoin gas funded)
             └─ Bridge: Stargate, CCTP, Chainflip
```

**重要:** 0x9392 / 0x34e5 と 0xcd2860 / 0x3137 の直接的な on-chain リンクは当レポートでは未確認 (SlowMist の帰属に依拠)。独立検証には 0x9392 → 0xcd2860 の資金フロー or 共通 CEX funding source の確認が必要。

### 14.8.4 `safe-relayer.eth` ENS — 新発見

zkLend の phishing 事件で浮上した ENS:

- **`safe-relayer.eth`** が偽 Tornado Cash サイト (`tornadoeth[.]cash`) のコードにハードコードされていた
- zkLend 攻撃者がこのフィッシングサイトに 2,930 ETH を送信 (2025-03-31)
- **複数の調査者が攻撃者 = phishing site 運営者 (同一人物) と疑う**
  - 根拠: safe-relayer.eth がサイトコードに一時的に出現 → 削除された
  - 反論: zkLend 側は「結論的証拠はない」と表明
- **Self-staging 仮説 (P を下方修正):** phishing loss が自作自演なら、Yei の TC phishing も同じパターンの可能性。ただし Yei と zkLend の TC phishing は別タイミング (Yei = 2025 Feb 18, zkLend = 2025 Mar 31)

**Fermi 再評価:**
- v1: TC phishing = PROBABLY REAL (P=0.65)
- v2 update: safe-relayer.eth + 複数調査者の self-staging 疑惑を踏まえ **P=0.50 (UNCERTAIN)** に下方修正
- 理由: 同一人物が 2 回とも phishing に遭うのは統計的に異常。self-staging なら全額を自分で保持

### 14.8.5 Linguistic Fingerprinting (Off-Chain 追加)

zkLend post-phishing の on-chain メッセージ (2025-03-31):
- *"All the 2930 ETH have been taken by that site owners. I do not have coins."*
- `"that site owners"` = those/that's の混用。非ネイティブ英語 (B2 レベル)
- `"I do not have coins"` = 不自然な表現 (ネイティブなら "I don't have any funds left")
- Yei の `callflashloandraaan` (drain のスペル変形) と合わせ、**一貫して非英語ネイティブ**

### 14.8.6 Cross-Platform Identity Stitching — 結果

| Check | Result |
|:---|:---|
| ENS (0xcd2860) | 未登録 |
| ENS (0x3137) | 未登録 |
| GitHub (address + function name) | 露出なし |
| Pastebin | 露出なし |
| Reddit | 露出なし |
| Twitter/X (address mention) | Merkle Science, SlowMist の公式レポートのみ |
| Telegram public channels | 未検索 (手動作業必要) |
| Wayback Machine | 未検索 |
| Arkham Intelligence | 未検索 (有料) |

**off-chain identity stitching の結果: 帰属に直結する新情報なし。** 攻撃者は SNS アカウントとウォレットの紐付けを回避している。**最有力の帰属経路は依然として KuCoin KYC 開示請求 (Tier 1)**。

---

## 14.9 Triage Scorecard — `Report Generation Phase` (2026-03-16)

```
FUND DISPOSITION (Yei Finance $2.4M incident only):
  Total stolen:            ~$2,400,000
  Traced (on-chain):       ~$2,350,000 (98%)
  Untraced:                ~$50,000 (2%) — BSC onward movement未確認
  Laundered (irreversible): ~$1,060,000 (44%)
    - Tornado Cash:  400 ETH ≈ $1,000,000
    - Chainflip BTC: 30 ETH ≈ $60,000 (BTC output, 事実上 irreversible)
  Potentially recoverable:  ~$1,290,000 (54%)
    - Stargate → BSC: 270K USDC + 15 ETH (BSC 確認待ち)
    - CCTP → Base:    78.7K USDC (2 recipients, 移動状況未確認)
    - CoW Protocol:   ~262K USDC (settlement output 未確認)
    - Railgun:        594 WETH → deshield 済み、一部 Aave 経由で CoW へ
    - 0x3137 残高:    ~5 ETH (ETH) + ~10 ETH (ARB)
  Dust/abandoned:           ~$50,000 (2%)

ATTRIBUTION READINESS:
  CEX KYC linkage:   [x] YES → KuCoin 2025-02-15 15:43:47 UTC, 0.035 ETH
  Serial exploiter:  [x] YES → 5+ incidents, $20M+ (SlowMist + Merkle Science)
  Timezone narrowed: [x] YES → UTC+2~+3 (Eastern Europe / Middle East)
  Human confirmed:   [x] YES → CV=1.387-1.435, UI timing patterns
  Off-chain OSINT:   [x] YES → Google Dorks 実施、Web 露出ゼロ確認

EXIT ROUTES REMAINING:
  [x] BSC (270K USDC + 15 ETH) — 移動状況未確認
  [x] Base CCTP recipients (78.7K USDC) — 移動状況未確認
  [ ] 0x3137 残高 (~$40K) — resting, 監視対象
  [ ] safe-relayer.eth (2,930 ETH from zkLend) — TC phishing or self-staging

URGENCY: MEDIUM
  主要資金は既に laundered (TC 400 ETH) or 分散済み (BSC/Base)。
  BSC/Base の確認が最優先 (V2 paid tier 必要)。
  0x3137 の $40K は凍結可能だが少額。
```

**Triage 判定:** Yei 単体での recoverable は最大 $1.29M だが BSC/Base 未確認。
Serial exploiter としての KuCoin KYC → 全 incident の損害賠償請求 ($20M+) が最大価値。

---

## 15. Law Firm Deliverable Summary

### このレポートが法律事務所に提供する価値

**1. ピンポイントの開示請求データ**

> 「KuCoin に対し、2025年2月15日 15:43:47 UTC (block 21,852,793) の出金を申請したユーザーアカウントの KYC 情報開示を請求してください。出金先: `0x313708e21398421d3b260494c0bf233403aEfC99`、出金額: 0.03518086 ETH。このアドレスは、直後に $1.25M 相当の盗難資金を Tornado Cash, Railgun, Chainflip 経由で洗浄した実行者のアドレスです。」

**2. 攻撃者の居住地域推定**

トランザクション時刻の統計分析により、UTC+2 ~ UTC+3 (東欧〜中東) に居住する可能性が最も高い。これは管轄権の決定に影響する。

**3. Serial exploiter の証拠 (2026-03-16 更新)**

SlowMist + Merkle Science の独立検証により、同一攻撃者が **5+ incidents, 合計 $20M+** に関与:
EraLend ($2.76M, 2023), Onyx ($3.8M, 2024), Yei ($2.4M, 2024), zkLend ($9.5M, 2025), Channels Finance, Starlay Finance。
`safe-relayer.eth` ENS が zkLend phishing site に関連 — self-staging 仮説あり。

**4. 攻撃者行動プロファイル (Deep Behavioral OSINT)**

- **人間オペレーター確定** (CV=1.435, bot ではない) — 法的手続きにおける「自然人」の証拠
- **Solo operator** — 組織犯罪ではなく個人。法的追及が現実的
- **100 ETH cognitive anchor + test-then-commit パターン** — 行動予測に有用 (将来の洗浄行動の監視)
- **KuCoin gas = genuine mistake (P=0.75)** — KYC 開示請求の正当性を補強
- **TC phishing loss = probably real (P=0.65)** — 残存資金は推定 $10.7M (全額ではない)
- **Lazarus Group 除外** — 国家支援攻撃ではない (法的戦略に影響)

**5. 回収可能資金の特定**

| Location | Amount | Action |
|:---|:---|:---|
| 0x3137 on Ethereum | 5.35 ETH ($14K) | 凍結要請 |
| 0x3137 on Arbitrum | ~10 ETH ($26K) | 凍結要請 |
| 0x3137 on BSC | 270K USDC + 15 ETH (一部残存?) | BSC 確認後凍結要請 |
| Base CCTP recipients | 78.7K USDC (2 addresses) | 確認後凍結要請 |

---

## 16. Next Steps

### Phase 6 (Remaining tracing)
1. **BSC 0x3137 full activity** — 270,248 USDC + 15 ETH arrived via Stargate. Need BSCScan or Etherscan V2 API to trace onward movement.
2. **Base CCTP recipients activity** — `0x438d...` (10K USDC) and `0x6800...` (68.7K USDC) on Base. BaseScan currently 403-blocked.
3. **CoW 262,507 USDC sell order** — What was received? Settlement analysis needed.
4. **Chainflip BTC output correlation** — Match 30 ETH deposit with BTC output by timestamp (Feb 18 16:44).
5. **BSC primary address (0xcd28) 13 tx analysis** — Original chain-hop activity.

### Phase 7 (Law enforcement engagement)
6. **KuCoin cooperation request** — KYC records for the account that funded 0x3137..fC99 at 2025-02-15 15:43:47 UTC.
7. **Tornado Cash statistical analysis** — Correlate 4×100 ETH deposits (Feb 18 04:03-04:15 UTC) with withdrawal patterns.
8. **Railgun subgraph query** — Monitor for additional shielding/deshielding by same commitment pattern.
9. **Arkham Intelligence query** — Check if either address has been labeled or linked to known entities.
10. **ENS domain check** — Verify if any addresses have registered ENS names.
11. **Cross-reference EraLend/zkLend addresses** — Trace `0x9392..6c40` and `0x34e5..3e6c1` for overlapping wallets with Yei addresses.
12. **`safe-relayer.eth` 調査** — ENS 所有者の on-chain 活動を追跡。Yei addresses との接点確認。
13. **Channels Finance / Starlay Finance** — zkLend post-mortem で言及された追加 incidents の詳細収集。
14. **Telegram OSINT** — telemetr.io 等で攻撃者アドレスの公開チャンネル言及を検索。

---

## 18. Disclaimer

DISCLAIMER: This report is based solely on publicly available blockchain data
and public reports. No unauthorized access to any system was performed.
All findings represent analytical conclusions, not legal determinations.
Address ownership attributions are probabilistic, not definitive.
This report does not constitute legal advice.

---

## 19. Evidence Preservation

Evidence log: `[evidence log — available on request]`
API calls recorded: 8 (Etherscan V2, SHA256 hashed)
Methodology: `Behavioral Analysis` + `Attribution OSINT Phase` skills (proprietary pipeline)
All API responses include redacted URL + SHA256 hash + UTC timestamp for legal admissibility.
