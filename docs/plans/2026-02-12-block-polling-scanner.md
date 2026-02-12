# Block Polling Scanner Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace indexer-based scanning with block polling to eliminate rich-indexer dependency.

**Architecture:** Poll blocks sequentially via `get_block()` RPC, check each tx output for stealth lock, match against local accounts, and build history locally. Track recent N block hashes for reorg detection via parent_hash verification.

**Tech Stack:** CKB RPC (`get_block`), heed (LMDB), existing stealth/CT matching logic

---

## Overview

Current state:
- Uses `get_cells_by_lock_prefix` and `get_transactions_by_lock_prefix` (indexer RPC)
- Requires rich-indexer for incremental scanning
- Complex deployment with extra indexer service

Target state:
- Poll blocks via `get_block(block_number)` 
- Check each tx output for stealth lock code_hash
- Match outputs against all local accounts
- Track inputs to detect spent cells
- Store recent N block hashes for reorg detection
- Build TxRecord locally

---

## Task 1: Add Config Fields for Scan Start Block

**Files:**
- Modify: `src/config.rs:34-66`

**Step 1: Add scan_start_block field to NetworkConfig**

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub name: String,
    pub rpc_url: String,
    /// Block number to start scanning from (default: 0).
    /// Set this to the stealth-lock deployment height to skip scanning old blocks.
    #[serde(default)]
    pub scan_start_block: u64,
}
```

**Step 2: Update testnet() default**

In `Config::testnet()`, set a reasonable default:
```rust
network: NetworkConfig {
    name: "testnet".to_string(),
    rpc_url: "https://testnet.ckb.dev".to_string(),
    scan_start_block: 0, // Will be updated when stealth-lock is deployed
},
```

**Step 3: Update devnet() default**

```rust
network: NetworkConfig {
    name: "devnet".to_string(),
    rpc_url: "http://127.0.0.1:8114".to_string(),
    scan_start_block: 0, // Devnet starts fresh
},
```

**Step 4: Update mainnet() default**

```rust
network: NetworkConfig {
    name: "mainnet".to_string(),
    rpc_url: "https://mainnet.ckb.dev".to_string(),
    scan_start_block: 0, // Will be updated when stealth-lock is deployed
},
```

**Step 5: Run check**

Run: `cargo check`
Expected: No errors

**Step 6: Commit**

```bash
git add src/config.rs
git commit -m "feat(config): add scan_start_block to NetworkConfig"
```

---

## Task 2: Add ScanState Data Structure

**Files:**
- Create: `src/domain/scan_state.rs`
- Modify: `src/domain/mod.rs`

**Step 1: Create scan_state.rs with ScanState struct**

```rust
//! Scan state tracking for block-based scanning.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Maximum number of recent blocks to track for reorg detection.
pub const MAX_RECENT_BLOCKS: usize = 64;

/// Scan state persisted in LMDB.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanState {
    /// Last successfully scanned block number.
    pub last_scanned_block: Option<u64>,
    /// Recent block hashes for reorg detection: (block_number, block_hash).
    /// Most recent is at the back.
    pub recent_blocks: VecDeque<(u64, [u8; 32])>,
}

impl ScanState {
    /// Create a new empty scan state.
    pub fn new() -> Self {
        Self {
            last_scanned_block: None,
            recent_blocks: VecDeque::new(),
        }
    }

    /// Add a new block to the recent blocks list.
    pub fn add_block(&mut self, block_number: u64, block_hash: [u8; 32]) {
        self.recent_blocks.push_back((block_number, block_hash));
        while self.recent_blocks.len() > MAX_RECENT_BLOCKS {
            self.recent_blocks.pop_front();
        }
        self.last_scanned_block = Some(block_number);
    }

    /// Get the expected parent hash for the next block.
    /// Returns None if no blocks have been scanned yet.
    pub fn expected_parent_hash(&self) -> Option<[u8; 32]> {
        self.recent_blocks.back().map(|(_, hash)| *hash)
    }

    /// Find the fork point when a reorg is detected.
    /// Returns the block number to roll back to (the last valid block).
    /// Returns None if no common ancestor is found in recent_blocks.
    pub fn find_fork_point(&self, parent_hash: &[u8; 32]) -> Option<u64> {
        // Search backwards through recent_blocks for matching hash
        for (block_number, hash) in self.recent_blocks.iter().rev() {
            if hash == parent_hash {
                return Some(*block_number);
            }
        }
        None
    }

    /// Roll back to a specific block number.
    /// Removes all blocks after the given block number.
    pub fn rollback_to(&mut self, block_number: u64) {
        while let Some(&(num, _)) = self.recent_blocks.back() {
            if num <= block_number {
                break;
            }
            self.recent_blocks.pop_back();
        }
        self.last_scanned_block = self.recent_blocks.back().map(|(num, _)| *num);
    }

    /// Get the next block number to scan.
    pub fn next_block_to_scan(&self, start_block: u64) -> u64 {
        match self.last_scanned_block {
            Some(last) => last + 1,
            None => start_block,
        }
    }

    /// Clear all state (for full rescan).
    pub fn clear(&mut self) {
        self.last_scanned_block = None;
        self.recent_blocks.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_state_add_block() {
        let mut state = ScanState::new();
        
        state.add_block(100, [1u8; 32]);
        assert_eq!(state.last_scanned_block, Some(100));
        assert_eq!(state.recent_blocks.len(), 1);
        
        state.add_block(101, [2u8; 32]);
        assert_eq!(state.last_scanned_block, Some(101));
        assert_eq!(state.recent_blocks.len(), 2);
    }

    #[test]
    fn test_scan_state_max_recent_blocks() {
        let mut state = ScanState::new();
        
        // Add more than MAX_RECENT_BLOCKS
        for i in 0..(MAX_RECENT_BLOCKS + 10) {
            state.add_block(i as u64, [i as u8; 32]);
        }
        
        assert_eq!(state.recent_blocks.len(), MAX_RECENT_BLOCKS);
        // First block should be trimmed
        assert_eq!(state.recent_blocks.front().unwrap().0, 10);
    }

    #[test]
    fn test_scan_state_expected_parent_hash() {
        let mut state = ScanState::new();
        assert_eq!(state.expected_parent_hash(), None);
        
        state.add_block(100, [0xab; 32]);
        assert_eq!(state.expected_parent_hash(), Some([0xab; 32]));
    }

    #[test]
    fn test_scan_state_find_fork_point() {
        let mut state = ScanState::new();
        state.add_block(100, [1u8; 32]);
        state.add_block(101, [2u8; 32]);
        state.add_block(102, [3u8; 32]);
        
        // Fork after block 101
        assert_eq!(state.find_fork_point(&[2u8; 32]), Some(101));
        
        // Unknown parent
        assert_eq!(state.find_fork_point(&[99u8; 32]), None);
    }

    #[test]
    fn test_scan_state_rollback() {
        let mut state = ScanState::new();
        state.add_block(100, [1u8; 32]);
        state.add_block(101, [2u8; 32]);
        state.add_block(102, [3u8; 32]);
        
        state.rollback_to(100);
        
        assert_eq!(state.last_scanned_block, Some(100));
        assert_eq!(state.recent_blocks.len(), 1);
        assert_eq!(state.recent_blocks.back().unwrap().0, 100);
    }

    #[test]
    fn test_scan_state_next_block() {
        let mut state = ScanState::new();
        assert_eq!(state.next_block_to_scan(50), 50); // Use start_block
        
        state.add_block(100, [1u8; 32]);
        assert_eq!(state.next_block_to_scan(50), 101); // Continue from last
    }
}
```

**Step 2: Export from domain/mod.rs**

Add to `src/domain/mod.rs`:
```rust
pub mod scan_state;
```

**Step 3: Run tests**

Run: `cargo test domain::scan_state`
Expected: All tests pass

**Step 4: Commit**

```bash
git add src/domain/scan_state.rs src/domain/mod.rs
git commit -m "feat(domain): add ScanState for block-based scanning"
```

---

## Task 3: Add RPC Method for get_block

**Files:**
- Modify: `src/infra/rpc.rs`

**Step 1: Add get_block method**

Add this method to `impl RpcClient`:

```rust
/// Get a block by block number.
pub fn get_block(&self, block_number: u64) -> Result<Option<ckb_jsonrpc_types::BlockView>> {
    let result = self.client.get_block_by_number(block_number.into())?;
    Ok(result)
}
```

**Step 2: Run check**

Run: `cargo check`
Expected: No errors

**Step 3: Commit**

```bash
git add src/infra/rpc.rs
git commit -m "feat(rpc): add get_block method for block polling"
```

---

## Task 4: Add Store Methods for ScanState

**Files:**
- Modify: `src/infra/store.rs`

**Step 1: Add imports**

Add to imports at top of store.rs:
```rust
use crate::domain::scan_state::ScanState;
```

**Step 2: Add scan state storage methods**

Add these methods to `impl Store`:

```rust
// ==================== Scan State Storage ====================

/// Key for storing scan state.
const SCAN_STATE_KEY: &str = "scan_state";

/// Save scan state.
pub fn save_scan_state(&self, state: &ScanState) -> Result<()> {
    self.save_metadata(SCAN_STATE_KEY, state)
}

/// Load scan state.
pub fn load_scan_state(&self) -> Result<ScanState> {
    Ok(self.load_metadata::<ScanState>(SCAN_STATE_KEY)?.unwrap_or_default())
}

/// Clear scan state (for full rescan).
pub fn clear_scan_state(&self) -> Result<()> {
    self.save_scan_state(&ScanState::new())
}
```

**Step 3: Update clear_all_cells_for_account to also clear scan state**

Note: Scan state is global (not per-account), so we need a separate method for full reset.

Add a new method:

```rust
/// Clear all data for a full rescan (scan state + all account cells).
pub fn clear_all_for_rescan(&self, account_ids: &[u64]) -> Result<()> {
    self.clear_scan_state()?;
    for &account_id in account_ids {
        self.clear_all_cells_for_account(account_id)?;
    }
    Ok(())
}
```

**Step 4: Run check**

Run: `cargo check`
Expected: No errors

**Step 5: Commit**

```bash
git add src/infra/store.rs
git commit -m "feat(store): add scan state persistence methods"
```

---

## Task 5: Create New Block-Based Scanner Module

**Files:**
- Create: `src/infra/block_scanner.rs`
- Modify: `src/infra/mod.rs`

**Step 1: Create block_scanner.rs with basic structure**

```rust
//! Block-based cell scanner for stealth address detection.
//!
//! Polls blocks via get_block() RPC instead of using indexer.
//! This eliminates the need for rich-indexer and simplifies deployment.

use ckb_jsonrpc_types::{BlockView, TransactionView};
use color_eyre::eyre::{Result, eyre};
use secp256k1::{PublicKey, SecretKey};
use tracing::{debug, info, warn};

use std::collections::{HashMap, HashSet};

use crate::{
    config::Config,
    domain::{
        account::Account,
        cell::{CtBalance, CtCell, CtInfoCell, StealthCell, TxRecord, aggregate_ct_balances},
        ct,
        ct_info::CtInfoData,
        scan_state::ScanState,
        stealth::{derive_shared_secret, matches_key},
    },
    infra::{rpc::RpcClient, store::Store},
};

/// Updates sent from background scanner to the main app.
#[derive(Debug, Clone, PartialEq)]
pub enum BlockScanUpdate {
    /// Scan started
    Started { is_full_rescan: bool },
    /// Progress update during block scanning
    Progress {
        current_block: u64,
        tip_block: u64,
        cells_found: u64,
    },
    /// Reorg detected and handled
    ReorgDetected {
        fork_block: u64,
        new_tip: u64,
    },
    /// Scan complete (caught up to tip)
    Complete {
        last_block: u64,
        total_stealth_cells: usize,
        total_ct_cells: usize,
        total_tx_records: usize,
    },
    /// Scan failed with error
    Error(String),
}

/// Block-based scanner that polls blocks instead of using indexer.
pub struct BlockScanner {
    rpc: RpcClient,
    store: Store,
    config: Config,
}

impl BlockScanner {
    pub fn new(config: Config, store: Store) -> Self {
        let rpc = RpcClient::new(config.clone());
        Self { rpc, store, config }
    }

    /// Get the stealth lock code hash as bytes.
    fn stealth_lock_code_hash(&self) -> Result<[u8; 32]> {
        let hash_str = self.config.contracts.stealth_lock_code_hash.trim_start_matches("0x");
        let bytes = hex::decode(hash_str)?;
        let arr: [u8; 32] = bytes.try_into()
            .map_err(|_| eyre!("Invalid stealth lock code hash length"))?;
        Ok(arr)
    }

    /// Get the CT token type code hash as bytes.
    fn ct_token_code_hash(&self) -> Result<Option<[u8; 32]>> {
        let hash_str = self.config.contracts.ct_token_code_hash.trim_start_matches("0x");
        if hash_str.chars().all(|c| c == '0') {
            return Ok(None);
        }
        let bytes = hex::decode(hash_str)?;
        let arr: [u8; 32] = bytes.try_into()
            .map_err(|_| eyre!("Invalid CT token code hash length"))?;
        Ok(Some(arr))
    }

    /// Get the CT info type code hash as bytes.
    fn ct_info_code_hash(&self) -> Result<Option<[u8; 32]>> {
        let hash_str = self.config.contracts.ct_info_code_hash.trim_start_matches("0x");
        if hash_str.chars().all(|c| c == '0') {
            return Ok(None);
        }
        let bytes = hex::decode(hash_str)?;
        let arr: [u8; 32] = bytes.try_into()
            .map_err(|_| eyre!("Invalid CT info code hash length"))?;
        Ok(Some(arr))
    }

    /// Get the current tip block number.
    pub fn get_tip_block_number(&self) -> Result<u64> {
        self.rpc.get_tip_block_number()
    }

    /// Get a reference to the RPC client.
    pub fn rpc(&self) -> &RpcClient {
        &self.rpc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_scan_update_variants() {
        let update = BlockScanUpdate::Progress {
            current_block: 100,
            tip_block: 200,
            cells_found: 5,
        };
        
        match update {
            BlockScanUpdate::Progress { current_block, .. } => {
                assert_eq!(current_block, 100);
            }
            _ => panic!("Expected Progress variant"),
        }
    }
}
```

**Step 2: Export from infra/mod.rs**

Add to `src/infra/mod.rs`:
```rust
pub mod block_scanner;
```

**Step 3: Run check**

Run: `cargo check`
Expected: No errors

**Step 4: Commit**

```bash
git add src/infra/block_scanner.rs src/infra/mod.rs
git commit -m "feat(infra): add BlockScanner module skeleton"
```

---

## Task 6: Implement Block Processing Logic

**Files:**
- Modify: `src/infra/block_scanner.rs`

**Step 1: Add process_block method**

Add this method to `impl BlockScanner`:

```rust
/// Result of processing a single block.
#[derive(Debug, Default)]
pub struct BlockProcessResult {
    /// New stealth cells found (per account).
    pub new_stealth_cells: HashMap<u64, Vec<StealthCell>>,
    /// New CT cells found (per account).
    pub new_ct_cells: HashMap<u64, Vec<CtCell>>,
    /// New CT-info cells found (per account).
    pub new_ct_info_cells: HashMap<u64, Vec<CtInfoCell>>,
    /// Spent out_points (per account).
    pub spent_out_points: HashMap<u64, Vec<Vec<u8>>>,
    /// New transaction records (per account).
    pub tx_records: HashMap<u64, Vec<TxRecord>>,
}
```

Add inside `impl BlockScanner`:

```rust
/// Process a single block for all accounts.
/// 
/// Returns cells found and spent cells for each account.
pub fn process_block(
    &self,
    block: &BlockView,
    accounts: &[Account],
) -> Result<BlockProcessResult> {
    let stealth_code_hash = self.stealth_lock_code_hash()?;
    let ct_code_hash = self.ct_token_code_hash()?;
    let ct_info_code_hash = self.ct_info_code_hash()?;

    let block_number: u64 = block.header.inner.number.into();
    let timestamp_ms: u64 = block.header.inner.timestamp.into();
    let timestamp = (timestamp_ms / 1000) as i64;

    // Prepare account keys
    let account_keys: Vec<_> = accounts
        .iter()
        .map(|a| (a.id, a.view_secret_key(), a.spend_public_key()))
        .collect();

    // Load existing out_points for spent detection
    let mut existing_out_points: HashMap<u64, HashSet<Vec<u8>>> = HashMap::new();
    for account in accounts {
        let stealth_cells = self.store.get_stealth_cells(account.id)?;
        let ct_cells = self.store.get_ct_cells(account.id)?;
        let ct_info_cells = self.store.get_ct_info_cells(account.id)?;
        
        let mut out_points: HashSet<Vec<u8>> = HashSet::new();
        for cell in stealth_cells {
            out_points.insert(cell.out_point);
        }
        for cell in ct_cells {
            out_points.insert(cell.out_point);
        }
        for cell in ct_info_cells {
            out_points.insert(cell.out_point);
        }
        existing_out_points.insert(account.id, out_points);
    }

    let mut result = BlockProcessResult::default();

    // Process each transaction in the block
    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        let tx_hash_h256 = &tx.hash;
        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(tx_hash_h256.as_bytes());

        // Track per-account involvement for this tx
        let mut account_ckb_delta: HashMap<u64, i64> = HashMap::new();
        let mut account_ct_delta: HashMap<u64, HashMap<[u8; 32], i64>> = HashMap::new();
        let mut account_involved: HashSet<u64> = HashSet::new();

        // Process outputs (cells being created)
        for (output_idx, output) in tx.inner.outputs.iter().enumerate() {
            // Check if this output uses stealth-lock
            if output.lock.code_hash.as_bytes() != stealth_code_hash {
                continue;
            }

            let lock_args = output.lock.args.as_bytes();
            
            // Build out_point bytes
            let mut out_point = Vec::with_capacity(36);
            out_point.extend_from_slice(tx_hash_h256.as_bytes());
            out_point.extend_from_slice(&(output_idx as u32).to_le_bytes());

            // Check ownership against all accounts
            for (account_id, view_key, spend_pub) in &account_keys {
                if !matches_key(lock_args, view_key, spend_pub) {
                    continue;
                }

                account_involved.insert(*account_id);
                let capacity: u64 = output.capacity.into();

                // Determine cell type
                let type_script = output.type_.as_ref();
                let is_ct = type_script
                    .map(|ts| ct_code_hash.as_ref().map(|h| ts.code_hash.as_bytes() == h).unwrap_or(false))
                    .unwrap_or(false);
                let is_ct_info = type_script
                    .map(|ts| ct_info_code_hash.as_ref().map(|h| ts.code_hash.as_bytes() == h).unwrap_or(false))
                    .unwrap_or(false);

                if is_ct {
                    // Process CT cell
                    let output_data = tx.inner.outputs_data
                        .get(output_idx)
                        .map(|d| d.as_bytes())
                        .unwrap_or(&[]);
                    
                    if let Some((commitment, encrypted_amount)) = Self::parse_ct_cell_data(output_data) {
                        if let Some(shared_secret) = derive_shared_secret(lock_args, view_key) {
                            if let Some(amount) = ct::decrypt_amount(&encrypted_amount, &shared_secret) {
                                let type_script_args = type_script
                                    .map(|ts| ts.args.as_bytes().to_vec())
                                    .unwrap_or_default();

                                let ct_cell = CtCell::new(
                                    out_point.clone(),
                                    type_script_args.clone(),
                                    commitment,
                                    encrypted_amount,
                                    [0u8; 32], // blinding factor placeholder
                                    amount,
                                    lock_args.to_vec(),
                                );

                                result.new_ct_cells
                                    .entry(*account_id)
                                    .or_default()
                                    .push(ct_cell);

                                // Track CT delta
                                let token_id = ct_cell.token_id;
                                *account_ct_delta
                                    .entry(*account_id)
                                    .or_default()
                                    .entry(token_id)
                                    .or_insert(0) += amount as i64;
                            }
                        }
                    }
                } else if is_ct_info {
                    // Process CT-info cell
                    let output_data = tx.inner.outputs_data
                        .get(output_idx)
                        .map(|d| d.as_bytes().to_vec())
                        .unwrap_or_default();

                    if let Ok(ct_info_data) = CtInfoData::from_bytes(&output_data) {
                        let type_args = type_script
                            .map(|ts| ts.args.as_bytes().to_vec())
                            .unwrap_or_default();

                        if type_args.len() >= 32 {
                            let mut token_id = [0u8; 32];
                            token_id.copy_from_slice(&type_args[0..32]);

                            let ct_info_cell = CtInfoCell::new(
                                out_point.clone(),
                                token_id,
                                ct_info_data.total_supply,
                                ct_info_data.supply_cap,
                                ct_info_data.flags,
                                capacity,
                                lock_args.to_vec(),
                            );

                            result.new_ct_info_cells
                                .entry(*account_id)
                                .or_default()
                                .push(ct_info_cell);

                            // Record genesis tx
                            let record = TxRecord::ct_genesis(tx_hash, token_id, timestamp, block_number);
                            result.tx_records
                                .entry(*account_id)
                                .or_default()
                                .push(record);
                        }
                    }
                } else {
                    // Plain stealth cell
                    let stealth_cell = StealthCell::new(
                        out_point.clone(),
                        capacity,
                        lock_args.to_vec(),
                    );

                    result.new_stealth_cells
                        .entry(*account_id)
                        .or_default()
                        .push(stealth_cell);

                    // Track CKB delta
                    *account_ckb_delta.entry(*account_id).or_insert(0) += capacity as i64;
                }

                // Cell can only belong to one account
                break;
            }
        }

        // Process inputs (cells being spent)
        // Skip cellbase (first tx in block has no real inputs)
        if tx_idx > 0 {
            for input in &tx.inner.inputs {
                let prev_tx_hash = input.previous_output.tx_hash.as_bytes();
                let prev_index: u32 = input.previous_output.index.into();

                // Build out_point for lookup
                let mut out_point = Vec::with_capacity(36);
                out_point.extend_from_slice(prev_tx_hash);
                out_point.extend_from_slice(&prev_index.to_le_bytes());

                // Check if any account owns this cell
                for (account_id, out_points) in &existing_out_points {
                    if out_points.contains(&out_point) {
                        account_involved.insert(*account_id);
                        result.spent_out_points
                            .entry(*account_id)
                            .or_default()
                            .push(out_point.clone());

                        // We need to look up the capacity/amount to calculate delta
                        // This requires fetching the previous tx or having it cached
                        // For now, we'll handle this by looking at our stored cells
                        if let Ok(cells) = self.store.get_stealth_cells(*account_id) {
                            if let Some(cell) = cells.iter().find(|c| c.out_point == out_point) {
                                *account_ckb_delta.entry(*account_id).or_insert(0) -= cell.capacity as i64;
                            }
                        }
                        if let Ok(cells) = self.store.get_ct_cells(*account_id) {
                            if let Some(cell) = cells.iter().find(|c| c.out_point == out_point) {
                                *account_ct_delta
                                    .entry(*account_id)
                                    .or_default()
                                    .entry(cell.token_id)
                                    .or_insert(0) -= cell.amount as i64;
                            }
                        }

                        break;
                    }
                }
            }
        }

        // Create TxRecords for involved accounts
        for account_id in account_involved {
            // CKB record
            if let Some(&delta) = account_ckb_delta.get(&account_id) {
                if delta != 0 {
                    let record = TxRecord::ckb(tx_hash, delta, timestamp, block_number);
                    result.tx_records
                        .entry(account_id)
                        .or_default()
                        .push(record);
                }
            }

            // CT records
            if let Some(ct_deltas) = account_ct_delta.get(&account_id) {
                for (&token_id, &delta) in ct_deltas {
                    if delta != 0 {
                        let record = TxRecord::ct(tx_hash, token_id, delta, timestamp, block_number);
                        result.tx_records
                            .entry(account_id)
                            .or_default()
                            .push(record);
                    }
                }
            }
        }
    }

    Ok(result)
}

/// Parse CT cell data (commitment || encrypted_amount).
fn parse_ct_cell_data(data: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if data.len() < 64 {
        return None;
    }
    let mut commitment = [0u8; 32];
    let mut encrypted_amount = [0u8; 32];
    commitment.copy_from_slice(&data[0..32]);
    encrypted_amount.copy_from_slice(&data[32..64]);
    Some((commitment, encrypted_amount))
}
```

**Step 2: Run check**

Run: `cargo check`
Expected: No errors

**Step 3: Commit**

```bash
git add src/infra/block_scanner.rs
git commit -m "feat(block_scanner): implement block processing logic"
```

---

## Task 7: Implement Scan Loop with Reorg Detection

**Files:**
- Modify: `src/infra/block_scanner.rs`

**Step 1: Add scan_blocks method**

Add this method to `impl BlockScanner`:

```rust
/// Scan blocks from last position up to tip.
/// 
/// Handles reorg detection by checking parent_hash against stored recent_blocks.
/// Returns the number of blocks processed.
pub fn scan_blocks(
    &self,
    accounts: &[Account],
    update_tx: Option<&tokio::sync::mpsc::UnboundedSender<BlockScanUpdate>>,
) -> Result<usize> {
    if accounts.is_empty() {
        return Ok(0);
    }

    let tip = self.get_tip_block_number()?;
    let mut state = self.store.load_scan_state()?;
    let start_block = self.config.network.scan_start_block;

    let mut current = state.next_block_to_scan(start_block);
    let mut blocks_processed = 0;
    let mut total_cells_found: u64 = 0;

    info!(
        "Starting block scan from {} to {} (tip)",
        current, tip
    );

    while current <= tip {
        // Fetch the block
        let block = match self.rpc.get_block(current)? {
            Some(b) => b,
            None => {
                warn!("Block {} not found, waiting...", current);
                break;
            }
        };

        let block_hash: [u8; 32] = block.header.hash.as_bytes().try_into()
            .map_err(|_| eyre!("Invalid block hash length"))?;
        let parent_hash: [u8; 32] = block.header.inner.parent_hash.as_bytes().try_into()
            .map_err(|_| eyre!("Invalid parent hash length"))?;

        // Check for reorg
        if let Some(expected_parent) = state.expected_parent_hash() {
            if parent_hash != expected_parent {
                // Reorg detected!
                info!(
                    "Reorg detected at block {}! Expected parent {:?}, got {:?}",
                    current,
                    hex::encode(&expected_parent[..8]),
                    hex::encode(&parent_hash[..8])
                );

                // Find fork point
                if let Some(fork_block) = state.find_fork_point(&parent_hash) {
                    info!("Fork point found at block {}", fork_block);
                    
                    // Rollback state
                    state.rollback_to(fork_block);
                    self.store.save_scan_state(&state)?;

                    // We need to rollback cell data too
                    // For simplicity, we'll do a full rescan from fork point
                    // A more sophisticated implementation would track per-block changes
                    for account in accounts {
                        self.store.clear_all_cells_for_account(account.id)?;
                    }
                    state.clear();
                    self.store.save_scan_state(&state)?;

                    // Notify about reorg
                    if let Some(tx) = update_tx {
                        let _ = tx.send(BlockScanUpdate::ReorgDetected {
                            fork_block,
                            new_tip: tip,
                        });
                    }

                    // Restart from fork point
                    current = fork_block + 1;
                    continue;
                } else {
                    // Can't find fork point in recent blocks - need full rescan
                    warn!("Fork point not found in recent blocks, initiating full rescan");
                    for account in accounts {
                        self.store.clear_all_cells_for_account(account.id)?;
                    }
                    state.clear();
                    self.store.save_scan_state(&state)?;
                    current = start_block;
                    continue;
                }
            }
        }

        // Process the block
        let result = self.process_block(&block, accounts)?;

        // Apply results to store
        for (account_id, cells) in &result.new_stealth_cells {
            if !cells.is_empty() {
                self.store.add_stealth_cells(*account_id, cells)?;
                total_cells_found += cells.len() as u64;
            }
        }
        for (account_id, cells) in &result.new_ct_cells {
            if !cells.is_empty() {
                self.store.add_ct_cells(*account_id, cells)?;
                total_cells_found += cells.len() as u64;
            }
        }
        for (account_id, cells) in &result.new_ct_info_cells {
            if !cells.is_empty() {
                self.store.add_ct_info_cells(*account_id, cells)?;
            }
        }
        for (account_id, out_points) in &result.spent_out_points {
            if !out_points.is_empty() {
                self.store.remove_spent_cells(*account_id, out_points)?;
                self.store.remove_spent_ct_cells(*account_id, out_points)?;
                self.store.remove_spent_ct_info_cells(*account_id, out_points)?;
            }
        }
        for (account_id, records) in &result.tx_records {
            for record in records {
                self.store.save_tx_record(*account_id, record)?;
            }
        }

        // Update scan state
        state.add_block(current, block_hash);
        self.store.save_scan_state(&state)?;

        blocks_processed += 1;

        // Send progress update periodically
        if let Some(tx) = update_tx {
            if blocks_processed % 100 == 0 || current == tip {
                let _ = tx.send(BlockScanUpdate::Progress {
                    current_block: current,
                    tip_block: tip,
                    cells_found: total_cells_found,
                });
            }
        }

        current += 1;
    }

    info!(
        "Block scan complete: {} blocks processed, {} cells found",
        blocks_processed, total_cells_found
    );

    Ok(blocks_processed)
}

/// Perform a full rescan from the start block.
pub fn full_rescan(
    &self,
    accounts: &[Account],
    update_tx: Option<&tokio::sync::mpsc::UnboundedSender<BlockScanUpdate>>,
) -> Result<usize> {
    info!("Starting full rescan...");

    // Clear all data
    let account_ids: Vec<u64> = accounts.iter().map(|a| a.id).collect();
    self.store.clear_all_for_rescan(&account_ids)?;

    // Notify
    if let Some(tx) = update_tx {
        let _ = tx.send(BlockScanUpdate::Started { is_full_rescan: true });
    }

    // Run scan
    self.scan_blocks(accounts, update_tx)
}

/// Spawn a background scan task.
pub fn spawn_background_scan(
    config: Config,
    store: Store,
    accounts: Vec<Account>,
    is_full_rescan: bool,
    update_tx: tokio::sync::mpsc::UnboundedSender<BlockScanUpdate>,
) {
    tokio::spawn(async move {
        let update_tx_clone = update_tx.clone();
        
        let _ = update_tx.send(BlockScanUpdate::Started { is_full_rescan });

        let result = tokio::task::spawn_blocking(move || {
            let scanner = BlockScanner::new(config, store);
            if is_full_rescan {
                scanner.full_rescan(&accounts, Some(&update_tx_clone))
            } else {
                scanner.scan_blocks(&accounts, Some(&update_tx_clone))
            }
        })
        .await;

        // Note: We can't easily get final counts here without re-querying store
        // The Complete update would need to be sent from within scan_blocks
    });
}
```

**Step 2: Run check**

Run: `cargo check`
Expected: No errors

**Step 3: Commit**

```bash
git add src/infra/block_scanner.rs
git commit -m "feat(block_scanner): implement scan loop with reorg detection"
```

---

## Task 8: Add Unit Tests for Block Scanner

**Files:**
- Modify: `src/infra/block_scanner.rs`

**Step 1: Add test module**

Add at the end of block_scanner.rs:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ct_cell_data_valid() {
        let mut data = vec![0u8; 64];
        data[0..32].copy_from_slice(&[1u8; 32]);
        data[32..64].copy_from_slice(&[2u8; 32]);
        
        let result = BlockScanner::parse_ct_cell_data(&data);
        assert!(result.is_some());
        
        let (commitment, encrypted) = result.unwrap();
        assert_eq!(commitment, [1u8; 32]);
        assert_eq!(encrypted, [2u8; 32]);
    }

    #[test]
    fn test_parse_ct_cell_data_too_short() {
        let data = vec![0u8; 32]; // Only 32 bytes
        let result = BlockScanner::parse_ct_cell_data(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_block_process_result_default() {
        let result = BlockProcessResult::default();
        assert!(result.new_stealth_cells.is_empty());
        assert!(result.new_ct_cells.is_empty());
        assert!(result.spent_out_points.is_empty());
    }
}
```

**Step 2: Run tests**

Run: `cargo test block_scanner`
Expected: All tests pass

**Step 3: Commit**

```bash
git add src/infra/block_scanner.rs
git commit -m "test(block_scanner): add unit tests"
```

---

## Task 9: Update App to Use Block Scanner

**Files:**
- Modify: `src/app.rs` (or wherever Scanner is used)

This task depends on understanding how the existing Scanner is integrated into the app. The key changes needed:

1. Replace `Scanner` imports with `BlockScanner`
2. Update `ScanUpdate` handling to use `BlockScanUpdate`
3. Change the spawn_background_scan call

**Step 1: Find and update Scanner usage**

Search for Scanner usage in app.rs and components. Replace:

```rust
// Old
use crate::infra::scanner::{Scanner, ScanUpdate};

// New
use crate::infra::block_scanner::{BlockScanner, BlockScanUpdate};
```

**Step 2: Update spawn calls**

```rust
// Old
Scanner::spawn_background_scan(config, store, accounts, is_full, tx);

// New
BlockScanner::spawn_background_scan(config, store, accounts, is_full, tx);
```

**Step 3: Update ScanUpdate match arms**

The variants are slightly different - update the match patterns accordingly.

**Step 4: Run check and test**

Run: `cargo check && cargo test`
Expected: No errors

**Step 5: Commit**

```bash
git add src/app.rs src/components/
git commit -m "refactor(app): switch from Scanner to BlockScanner"
```

---

## Task 10: Integration Testing

**Files:**
- Modify: `tests/integration/mod.rs` (if exists)

**Step 1: Add block scanner integration test**

Create a test that:
1. Creates a test wallet with an account
2. Uses BlockScanner to scan blocks
3. Verifies cells are found correctly

This requires a running devnet with stealth-lock deployed.

**Step 2: Run integration tests**

Run: `cargo test --features test-utils --test integration`
Expected: Tests pass

**Step 3: Commit**

```bash
git add tests/
git commit -m "test(integration): add block scanner tests"
```

---

## Task 11: Cleanup Old Scanner (Optional)

**Files:**
- Delete: `src/infra/scanner.rs` (or keep for reference)
- Modify: `src/infra/mod.rs`

After verifying block scanner works correctly, the old indexer-based scanner can be removed or deprecated.

**Step 1: Remove old scanner module export**

In `src/infra/mod.rs`, remove or comment out:
```rust
// pub mod scanner;  // Deprecated: use block_scanner instead
```

**Step 2: Run full test suite**

Run: `cargo test`
Expected: All tests pass

**Step 3: Commit**

```bash
git add src/infra/mod.rs
git commit -m "chore: deprecate old indexer-based scanner"
```

---

## Summary

This plan implements a block-polling scanner that:

1. **Eliminates indexer dependency** - Uses `get_block()` instead of indexer RPC
2. **Supports incremental scanning** - Tracks last scanned block in `ScanState`
3. **Handles reorgs** - Stores recent N block hashes, detects via parent_hash mismatch
4. **Maintains compatibility** - Same cell types, same store methods
5. **Configurable start block** - New `scan_start_block` in config

Key files changed:
- `src/config.rs` - Add `scan_start_block`
- `src/domain/scan_state.rs` - New state tracking
- `src/infra/rpc.rs` - Add `get_block()`
- `src/infra/store.rs` - Add scan state methods
- `src/infra/block_scanner.rs` - New scanner implementation
