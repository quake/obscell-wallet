//! Block-based cell scanner for stealth address detection.
//!
//! Polls blocks via get_block() RPC instead of using indexer.
//! This eliminates the need for rich-indexer and simplifies deployment.

use ckb_jsonrpc_types::BlockView;
use color_eyre::eyre::{eyre, Result};
use tracing::{info, warn};

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
                        .map(|ts| {
                            ct_code_hash
                                .as_ref()
                                .map(|h| ts.code_hash.as_bytes() == h)
                                .unwrap_or(false)
                        })
                        .unwrap_or(false);
                    let is_ct_info = type_script
                        .map(|ts| {
                            ct_info_code_hash
                                .as_ref()
                                .map(|h| ts.code_hash.as_bytes() == h)
                                .unwrap_or(false)
                        })
                        .unwrap_or(false);

                    if is_ct {
                        // Process CT cell
                        let output_data = tx
                            .inner
                            .outputs_data
                            .get(output_idx)
                            .map(|d| d.as_bytes())
                            .unwrap_or(&[]);

                        if let Some((commitment, encrypted_amount)) =
                            Self::parse_ct_cell_data(output_data)
                        {
                            if let Some(shared_secret) = derive_shared_secret(lock_args, view_key) {
                                if let Some(amount) =
                                    ct::decrypt_amount(&encrypted_amount, &shared_secret)
                                {
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

                                    result
                                        .new_ct_cells
                                        .entry(*account_id)
                                        .or_default()
                                        .push(ct_cell);

                                    // Track CT delta
                                    let mut token_id = [0u8; 32];
                                    if type_script_args.len() >= 32 {
                                        token_id.copy_from_slice(&type_script_args[0..32]);
                                    }
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
                        let output_data = tx
                            .inner
                            .outputs_data
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

                                result
                                    .new_ct_info_cells
                                    .entry(*account_id)
                                    .or_default()
                                    .push(ct_info_cell);

                                // Record genesis tx
                                let record = TxRecord::ct_genesis(
                                    tx_hash,
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
                            StealthCell::new(out_point.clone(), capacity, lock_args.to_vec());

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
                            result
                                .spent_out_points
                                .entry(*account_id)
                                .or_default()
                                .push(out_point.clone());

                            // We need to look up the capacity/amount to calculate delta
                            // This requires fetching the previous tx or having it cached
                            // For now, we'll handle this by looking at our stored cells
                            if let Ok(cells) = self.store.get_stealth_cells(*account_id) {
                                if let Some(cell) = cells.iter().find(|c| c.out_point == out_point)
                                {
                                    *account_ckb_delta.entry(*account_id).or_insert(0) -=
                                        cell.capacity as i64;
                                }
                            }
                            if let Ok(cells) = self.store.get_ct_cells(*account_id) {
                                if let Some(cell) = cells.iter().find(|c| c.out_point == out_point)
                                {
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
                        result
                            .tx_records
                            .entry(account_id)
                            .or_default()
                            .push(record);
                    }
                }

                // CT records
                if let Some(ct_deltas) = account_ct_delta.get(&account_id) {
                    for (&token_id, &delta) in ct_deltas {
                        if delta != 0 {
                            let record =
                                TxRecord::ct(tx_hash, token_id, delta, timestamp, block_number);
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

            let _result = tokio::task::spawn_blocking(move || {
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
            BlockScanUpdate::ReorgDetected { fork_block, new_tip } => {
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
