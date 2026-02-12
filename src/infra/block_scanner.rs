//! Block-based cell scanner for stealth address detection.
//!
//! Polls blocks via get_block() RPC instead of using indexer.
//! This eliminates the need for rich-indexer and simplifies deployment.

use ckb_jsonrpc_types::{BlockView, TransactionView};
use color_eyre::eyre::{eyre, Result};
use secp256k1::{PublicKey, SecretKey};
use tracing::{debug, info, warn};

use std::collections::{HashMap, HashSet};

use crate::{
    config::Config,
    domain::{
        account::Account,
        cell::{aggregate_ct_balances, CtBalance, CtCell, CtInfoCell, StealthCell, TxRecord},
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
