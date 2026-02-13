//! Block-based cell scanner for stealth address detection.
//!
//! Polls blocks via get_packed_block() RPC instead of using indexer.
//! This eliminates the need for rich-indexer and simplifies deployment.
//! Uses packed block format for more efficient network transfer.

use ckb_types::{packed, prelude::*};
use color_eyre::eyre::{Result, eyre};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use std::collections::{HashMap, HashSet};

use crate::{
    config::Config,
    domain::{
        account::Account,
        cell::{CtCell, CtInfoCell, StealthCell, TxRecord},
        ct,
        ct_info::CtInfoData,
        stealth::{derive_shared_secret, matches_key},
    },
    infra::{rpc::RpcClient, store::Store},
};

/// Updates sent from background scanner to the main app.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    ReorgDetected { fork_block: u64, new_tip: u64 },
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
        let hash_str = self
            .config
            .contracts
            .stealth_lock_code_hash
            .trim_start_matches("0x");
        let bytes = hex::decode(hash_str)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| eyre!("Invalid stealth lock code hash length"))?;
        Ok(arr)
    }

    /// Get the CT token type code hash as bytes.
    fn ct_token_code_hash(&self) -> Result<Option<[u8; 32]>> {
        let hash_str = self
            .config
            .contracts
            .ct_token_code_hash
            .trim_start_matches("0x");
        if hash_str.chars().all(|c| c == '0') {
            return Ok(None);
        }
        let bytes = hex::decode(hash_str)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| eyre!("Invalid CT token code hash length"))?;
        Ok(Some(arr))
    }

    /// Get the CT info type code hash as bytes.
    fn ct_info_code_hash(&self) -> Result<Option<[u8; 32]>> {
        let hash_str = self
            .config
            .contracts
            .ct_info_code_hash
            .trim_start_matches("0x");
        if hash_str.chars().all(|c| c == '0') {
            return Ok(None);
        }
        let bytes = hex::decode(hash_str)?;
        let arr: [u8; 32] = bytes
            .try_into()
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

    /// Fetch a packed block with exponential backoff retry on transient errors.
    ///
    /// Retries up to 5 times with delays: 100ms, 200ms, 400ms, 800ms, 1600ms
    /// Uses get_packed_block for more efficient network transfer.
    /// Note: Uses BlockV1 format (CKB2023+).
    fn get_block_with_retry(&self, block_number: u64) -> Result<Option<packed::BlockV1>> {
        const MAX_RETRIES: u32 = 5;
        const INITIAL_DELAY_MS: u64 = 100;

        let mut attempt = 0;
        loop {
            match self.rpc.get_packed_block(block_number) {
                Ok(result) => return Ok(result),
                Err(e) => {
                    attempt += 1;
                    if attempt >= MAX_RETRIES {
                        return Err(e);
                    }

                    // Check if this looks like a transient error (rate limit, network, etc.)
                    let err_str = e.to_string().to_lowercase();
                    let is_transient = err_str.contains("rate")
                        || err_str.contains("limit")
                        || err_str.contains("timeout")
                        || err_str.contains("connection")
                        || err_str.contains("temporarily")
                        || err_str.contains("503")
                        || err_str.contains("429");

                    if !is_transient {
                        // Permanent error, don't retry
                        return Err(e);
                    }

                    let delay_ms = INITIAL_DELAY_MS * (1 << (attempt - 1)); // exponential backoff
                    warn!(
                        "RPC error fetching block {}, attempt {}/{}, retrying in {}ms: {}",
                        block_number, attempt, MAX_RETRIES, delay_ms, e
                    );
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                }
            }
        }
    }

    /// Process a single packed block for all accounts.
    ///
    /// Returns cells found and spent cells for each account.
    /// Note: Uses BlockV1 format (CKB2023+).
    pub fn process_block(
        &self,
        block: &packed::BlockV1,
        accounts: &[Account],
    ) -> Result<BlockProcessResult> {
        let stealth_code_hash = self.stealth_lock_code_hash()?;
        let ct_code_hash = self.ct_token_code_hash()?;
        let ct_info_code_hash = self.ct_info_code_hash()?;

        let header = block.header();
        let block_number: u64 = header.raw().number().unpack();
        let timestamp_ms: u64 = header.raw().timestamp().unpack();
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
        for (tx_idx, tx) in block.transactions().into_iter().enumerate() {
            let tx_hash: packed::Byte32 = tx.calc_tx_hash();
            let tx_hash_bytes: [u8; 32] = tx_hash.into();

            // Track per-account involvement for this tx
            let mut account_ckb_delta: HashMap<u64, i64> = HashMap::new();
            let mut account_ct_delta: HashMap<u64, HashMap<[u8; 32], i64>> = HashMap::new();
            let mut account_involved: HashSet<u64> = HashSet::new();

            let raw_tx = tx.raw();
            let outputs = raw_tx.outputs();
            let outputs_data = raw_tx.outputs_data();

            // Process outputs (cells being created)
            for output_idx in 0..outputs.len() {
                let output = outputs.get(output_idx).unwrap();
                let lock_script = output.lock();

                // Check if this output uses stealth-lock
                let lock_code_hash: [u8; 32] = lock_script
                    .code_hash()
                    .as_slice()
                    .try_into()
                    .map_err(|_| eyre!("Invalid lock code hash length"))?;
                if lock_code_hash != stealth_code_hash {
                    continue;
                }

                let lock_args = lock_script.args().raw_data();
                let lock_args_bytes = lock_args.as_ref();

                // Build out_point bytes
                let mut out_point = Vec::with_capacity(36);
                out_point.extend_from_slice(&tx_hash_bytes);
                out_point.extend_from_slice(&(output_idx as u32).to_le_bytes());

                // Check ownership against all accounts
                for (account_id, view_key, spend_pub) in &account_keys {
                    if !matches_key(lock_args_bytes, view_key, spend_pub) {
                        continue;
                    }

                    account_involved.insert(*account_id);
                    let capacity: u64 = output.capacity().unpack();

                    // Determine cell type
                    let type_script_opt = output.type_().to_opt();
                    let (is_ct, is_ct_info) = if let Some(ref ts) = type_script_opt {
                        let type_code_hash: [u8; 32] = ts
                            .code_hash()
                            .as_slice()
                            .try_into()
                            .map_err(|_| eyre!("Invalid type code hash length"))?;
                        let is_ct = ct_code_hash
                            .as_ref()
                            .map(|h| &type_code_hash == h)
                            .unwrap_or(false);
                        let is_ct_info = ct_info_code_hash
                            .as_ref()
                            .map(|h| &type_code_hash == h)
                            .unwrap_or(false);
                        (is_ct, is_ct_info)
                    } else {
                        (false, false)
                    };

                    if is_ct {
                        // Process CT cell
                        let output_data = outputs_data
                            .get(output_idx)
                            .map(|d| d.raw_data())
                            .unwrap_or_default();
                        let output_data_bytes = output_data.as_ref();

                        if let Some((commitment, encrypted_amount)) =
                            Self::parse_ct_cell_data(output_data_bytes)
                            && let Some(shared_secret) =
                                derive_shared_secret(lock_args_bytes, view_key)
                            && let Some(amount) =
                                ct::decrypt_amount(&encrypted_amount, &shared_secret)
                        {
                            let type_script_args = type_script_opt
                                .as_ref()
                                .map(|ts| ts.args().raw_data().to_vec())
                                .unwrap_or_default();

                            let ct_cell = CtCell::new(
                                out_point.clone(),
                                type_script_args.clone(),
                                commitment,
                                encrypted_amount,
                                [0u8; 32], // blinding factor placeholder
                                amount,
                                lock_args_bytes.to_vec(),
                            );

                            result
                                .new_ct_cells
                                .entry(*account_id)
                                .or_default()
                                .push(ct_cell);

                            // Track CT delta - use last 32 bytes as token_id
                            // (type_script_args = ct_info_code_hash || token_id)
                            let mut token_id = [0u8; 32];
                            if type_script_args.len() >= 32 {
                                let start = type_script_args.len() - 32;
                                token_id.copy_from_slice(&type_script_args[start..]);
                            }
                            *account_ct_delta
                                .entry(*account_id)
                                .or_default()
                                .entry(token_id)
                                .or_insert(0) += amount as i64;
                        }
                    } else if is_ct_info {
                        // Process CT-info cell
                        let output_data = outputs_data
                            .get(output_idx)
                            .map(|d| d.raw_data().to_vec())
                            .unwrap_or_default();

                        if let Ok(ct_info_data) = CtInfoData::from_bytes(&output_data) {
                            let type_args = type_script_opt
                                .as_ref()
                                .map(|ts| ts.args().raw_data().to_vec())
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
                                    lock_args_bytes.to_vec(),
                                );

                                result
                                    .new_ct_info_cells
                                    .entry(*account_id)
                                    .or_default()
                                    .push(ct_info_cell);

                                // Record genesis tx
                                let record = TxRecord::ct_genesis(
                                    tx_hash_bytes,
                                    token_id,
                                    timestamp,
                                    block_number,
                                );
                                result
                                    .tx_records
                                    .entry(*account_id)
                                    .or_default()
                                    .push(record);
                            }
                        }
                    } else {
                        // Plain stealth cell
                        let stealth_cell =
                            StealthCell::new(out_point.clone(), capacity, lock_args_bytes.to_vec());

                        result
                            .new_stealth_cells
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
                for input in raw_tx.inputs().into_iter() {
                    let prev_out_point = input.previous_output();
                    let prev_tx_hash = prev_out_point.tx_hash();
                    let prev_index: u32 = prev_out_point.index().unpack();

                    // Build out_point for lookup
                    let mut out_point = Vec::with_capacity(36);
                    out_point.extend_from_slice(prev_tx_hash.as_slice());
                    out_point.extend_from_slice(&prev_index.to_le_bytes());

                    // Check if any account owns this cell
                    for (account_id, out_points) in &existing_out_points {
                        if out_points.contains(&out_point) {
                            account_involved.insert(*account_id);
                            result
                                .spent_out_points
                                .entry(*account_id)
                                .or_default()
                                .push(out_point.clone());

                            // We need to look up the capacity/amount to calculate delta
                            // This requires fetching the previous tx or having it cached
                            // For now, we'll handle this by looking at our stored cells
                            if let Ok(cells) = self.store.get_stealth_cells(*account_id)
                                && let Some(cell) = cells.iter().find(|c| c.out_point == out_point)
                            {
                                *account_ckb_delta.entry(*account_id).or_insert(0) -=
                                    cell.capacity as i64;
                            }
                            if let Ok(cells) = self.store.get_ct_cells(*account_id)
                                && let Some(cell) = cells.iter().find(|c| c.out_point == out_point)
                            {
                                *account_ct_delta
                                    .entry(*account_id)
                                    .or_default()
                                    .entry(cell.token_id)
                                    .or_insert(0) -= cell.amount as i64;
                            }

                            break;
                        }
                    }
                }
            }

            // Create TxRecords for involved accounts
            for account_id in account_involved {
                // CKB record
                if let Some(&delta) = account_ckb_delta.get(&account_id)
                    && delta != 0
                {
                    let record = TxRecord::ckb(tx_hash_bytes, delta, timestamp, block_number);
                    result
                        .tx_records
                        .entry(account_id)
                        .or_default()
                        .push(record);
                }

                // CT records
                if let Some(ct_deltas) = account_ct_delta.get(&account_id) {
                    for (&token_id, &delta) in ct_deltas {
                        if delta != 0 {
                            let record = TxRecord::ct(
                                tx_hash_bytes,
                                token_id,
                                delta,
                                timestamp,
                                block_number,
                            );
                            result
                                .tx_records
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

    /// Scan blocks from last position up to tip.
    ///
    /// Handles reorg detection by checking parent_hash against stored recent_blocks.
    /// Returns the number of blocks processed.
    pub fn scan_blocks(
        &self,
        accounts: &[Account],
        update_tx: Option<&tokio::sync::mpsc::UnboundedSender<BlockScanUpdate>>,
    ) -> Result<usize> {
        self.scan_blocks_from_height(accounts, self.config.network.scan_start_block, update_tx)
    }

    /// Scan blocks from a specific height up to tip.
    ///
    /// Handles reorg detection by checking parent_hash against stored recent_blocks.
    /// Returns the number of blocks processed.
    pub fn scan_blocks_from_height(
        &self,
        accounts: &[Account],
        start_block: u64,
        update_tx: Option<&tokio::sync::mpsc::UnboundedSender<BlockScanUpdate>>,
    ) -> Result<usize> {
        if accounts.is_empty() {
            return Ok(0);
        }

        let tip = self.get_tip_block_number()?;
        let mut state = self.store.load_scan_state()?;

        let mut current = state.next_block_to_scan(start_block);
        let mut blocks_processed = 0;
        let mut total_cells_found: u64 = 0;

        // Log scan state on startup
        debug!(
            "Scan state: start_block={}, last_scanned={:?}, recent_blocks_count={}, next_to_scan={}",
            start_block,
            state.last_scanned_block,
            state.recent_blocks.len(),
            current
        );

        // Only log if there are blocks to scan
        if current <= tip {
            info!("Starting block scan from {} to {} (tip)", current, tip);
        } else {
            debug!("Already synced to tip {}, no new blocks to scan", tip);
            // Send a progress update with current tip even when already synced
            if let Some(tx) = update_tx {
                let last_scanned = state.last_scanned_block.unwrap_or(start_block);
                let _ = tx.send(BlockScanUpdate::Progress {
                    current_block: last_scanned,
                    tip_block: tip,
                    cells_found: 0,
                });
            }
        }

        while current <= tip {
            // Fetch the block with retry on transient errors
            let block = match self.get_block_with_retry(current) {
                Ok(Some(b)) => b,
                Ok(None) => {
                    warn!("Block {} not found, waiting...", current);
                    break;
                }
                Err(e) => {
                    // Permanent error after retries - report and stop
                    warn!("Failed to fetch block {} after retries: {}", current, e);
                    if let Some(tx) = update_tx {
                        let _ = tx.send(BlockScanUpdate::Error(format!(
                            "RPC error at block {}: {}",
                            current, e
                        )));
                    }
                    return Err(e);
                }
            };

            let block_hash: [u8; 32] = block.header().calc_header_hash().into();
            let parent_hash: [u8; 32] = block.header().raw().parent_hash().into();

            // Check for reorg
            if let Some(expected_parent) = state.expected_parent_hash()
                && parent_hash != expected_parent
            {
                // Reorg detected!
                warn!(
                    "Reorg detected at block {}! Expected parent {:?}, got {:?}",
                    current,
                    hex::encode(&expected_parent[..8]),
                    hex::encode(&parent_hash[..8])
                );

                // Find fork point
                if let Some(fork_block) = state.find_fork_point(&parent_hash) {
                    info!("Fork point found at block {}", fork_block);

                    // Rollback state to fork point
                    state.rollback_to(fork_block);

                    // Clear all cell data since we don't have per-block undo logs.
                    // We'll rescan from fork_block + 1 to rebuild the correct state.
                    for account in accounts {
                        self.store.clear_all_cells_for_account(account.id)?;
                    }

                    // Save state AFTER clearing cells but WITHOUT calling clear()
                    // This preserves the fork point info so we continue from fork_block + 1
                    self.store.save_scan_state(&state)?;

                    // Notify about reorg
                    if let Some(tx) = update_tx {
                        let _ = tx.send(BlockScanUpdate::ReorgDetected {
                            fork_block,
                            new_tip: tip,
                        });
                    }

                    // Restart scanning from fork point + 1
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
                    self.store
                        .remove_spent_ct_info_cells(*account_id, out_points)?;
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

            // Send progress update every 10 blocks
            if let Some(tx) = update_tx
                && (blocks_processed % 10 == 0 || current == tip)
            {
                let _ = tx.send(BlockScanUpdate::Progress {
                    current_block: current,
                    tip_block: tip,
                    cells_found: total_cells_found,
                });
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
        self.full_rescan_from_height(accounts, None, update_tx)
    }

    /// Perform a full rescan from a specific block height.
    /// If `start_height` is None, uses the config's scan_start_block.
    pub fn full_rescan_from_height(
        &self,
        accounts: &[Account],
        start_height: Option<u64>,
        update_tx: Option<&tokio::sync::mpsc::UnboundedSender<BlockScanUpdate>>,
    ) -> Result<usize> {
        let start = start_height.unwrap_or(self.config.network.scan_start_block);
        info!("Starting full rescan from block {}...", start);

        // Clear all data
        let account_ids: Vec<u64> = accounts.iter().map(|a| a.id).collect();
        self.store.clear_all_for_rescan(&account_ids)?;

        // Notify
        if let Some(tx) = update_tx {
            let _ = tx.send(BlockScanUpdate::Started {
                is_full_rescan: true,
            });
        }

        // Run scan from specified height
        self.scan_blocks_from_height(accounts, start, update_tx)
    }

    /// Spawn a background scan task.
    /// If `start_height` is Some, performs a full rescan from that height.
    /// If `start_height` is None and `is_full_rescan` is true, uses config's scan_start_block.
    pub fn spawn_background_scan(
        config: Config,
        store: Store,
        accounts: Vec<Account>,
        is_full_rescan: bool,
        start_height: Option<u64>,
        update_tx: tokio::sync::mpsc::UnboundedSender<BlockScanUpdate>,
    ) {
        tokio::spawn(async move {
            let update_tx_clone = update_tx.clone();
            let update_tx_final = update_tx.clone();
            let store_clone = store.clone();
            let account_ids: Vec<u64> = accounts.iter().map(|a| a.id).collect();

            let _ = update_tx.send(BlockScanUpdate::Started { is_full_rescan });

            let result = tokio::task::spawn_blocking(move || {
                let scanner = BlockScanner::new(config, store);
                if is_full_rescan {
                    scanner.full_rescan_from_height(&accounts, start_height, Some(&update_tx_clone))
                } else {
                    scanner.scan_blocks(&accounts, Some(&update_tx_clone))
                }
            })
            .await;

            // Handle result and send final update
            match result {
                Ok(Ok(_blocks_processed)) => {
                    // Count cells from store for the Complete message
                    let mut total_stealth = 0;
                    let mut total_ct = 0;
                    let mut total_tx = 0;
                    for account_id in &account_ids {
                        if let Ok(cells) = store_clone.get_stealth_cells(*account_id) {
                            total_stealth += cells.len();
                        }
                        if let Ok(cells) = store_clone.get_ct_cells(*account_id) {
                            total_ct += cells.len();
                        }
                        if let Ok(history) = store_clone.get_tx_history(*account_id) {
                            total_tx += history.len();
                        }
                    }
                    let last_block = store_clone
                        .load_scan_state()
                        .ok()
                        .and_then(|s| s.last_scanned_block)
                        .unwrap_or(0);

                    let _ = update_tx_final.send(BlockScanUpdate::Complete {
                        last_block,
                        total_stealth_cells: total_stealth,
                        total_ct_cells: total_ct,
                        total_tx_records: total_tx,
                    });
                }
                Ok(Err(e)) => {
                    // Scan returned an error
                    let _ = update_tx_final.send(BlockScanUpdate::Error(e.to_string()));
                }
                Err(e) => {
                    // Task panicked
                    let _ = update_tx_final
                        .send(BlockScanUpdate::Error(format!("Scan task panicked: {}", e)));
                }
            }
        });
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
    fn test_parse_ct_cell_data_empty() {
        let data = vec![];
        let result = BlockScanner::parse_ct_cell_data(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_ct_cell_data_extra_bytes() {
        // Extra bytes beyond 64 should be ignored
        let mut data = vec![0u8; 128];
        data[0..32].copy_from_slice(&[0xaa; 32]);
        data[32..64].copy_from_slice(&[0xbb; 32]);
        data[64..128].copy_from_slice(&[0xff; 64]); // extra bytes

        let result = BlockScanner::parse_ct_cell_data(&data);
        assert!(result.is_some());

        let (commitment, encrypted) = result.unwrap();
        assert_eq!(commitment, [0xaa; 32]);
        assert_eq!(encrypted, [0xbb; 32]);
    }

    #[test]
    fn test_block_process_result_default() {
        let result = BlockProcessResult::default();
        assert!(result.new_stealth_cells.is_empty());
        assert!(result.new_ct_cells.is_empty());
        assert!(result.new_ct_info_cells.is_empty());
        assert!(result.spent_out_points.is_empty());
        assert!(result.tx_records.is_empty());
    }

    #[test]
    fn test_block_scan_update_started() {
        let update = BlockScanUpdate::Started {
            is_full_rescan: true,
        };
        match update {
            BlockScanUpdate::Started { is_full_rescan } => {
                assert!(is_full_rescan);
            }
            _ => panic!("Expected Started variant"),
        }
    }

    #[test]
    fn test_block_scan_update_reorg_detected() {
        let update = BlockScanUpdate::ReorgDetected {
            fork_block: 500,
            new_tip: 600,
        };
        match update {
            BlockScanUpdate::ReorgDetected {
                fork_block,
                new_tip,
            } => {
                assert_eq!(fork_block, 500);
                assert_eq!(new_tip, 600);
            }
            _ => panic!("Expected ReorgDetected variant"),
        }
    }

    #[test]
    fn test_block_scan_update_complete() {
        let update = BlockScanUpdate::Complete {
            last_block: 1000,
            total_stealth_cells: 10,
            total_ct_cells: 5,
            total_tx_records: 15,
        };
        match update {
            BlockScanUpdate::Complete {
                last_block,
                total_stealth_cells,
                total_ct_cells,
                total_tx_records,
            } => {
                assert_eq!(last_block, 1000);
                assert_eq!(total_stealth_cells, 10);
                assert_eq!(total_ct_cells, 5);
                assert_eq!(total_tx_records, 15);
            }
            _ => panic!("Expected Complete variant"),
        }
    }

    #[test]
    fn test_block_scan_update_error() {
        let update = BlockScanUpdate::Error("Test error".to_string());
        match update {
            BlockScanUpdate::Error(msg) => {
                assert_eq!(msg, "Test error");
            }
            _ => panic!("Expected Error variant"),
        }
    }
}
