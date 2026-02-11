//! Cell scanning service for stealth address detection.
//!
//! Scans the CKB blockchain for cells that belong to the wallet's accounts
//! using the stealth address protocol.

use ckb_jsonrpc_types::{Either, JsonBytes};
use color_eyre::eyre::Result;
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use std::collections::{HashMap, HashSet};

use crate::{
    config::Config,
    domain::{
        account::Account,
        cell::{CtBalance, CtCell, CtInfoCell, StealthCell, TxRecord, aggregate_ct_balances},
        ct,
        ct_info::CtInfoData,
        stealth::{derive_shared_secret, matches_key},
    },
    infra::{rpc::RpcClient, store::Store},
};

/// Scan cursor stored in LMDB for resuming scans.
const SCAN_CURSOR_KEY: &str = "scan_cursor";

/// Number of cells to fetch per RPC call.
const CELLS_PER_PAGE: u32 = 100;

/// Updates sent from background scanner to the main app.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScanUpdate {
    /// Scan started
    Started { is_full_rescan: bool },
    /// Progress update during cell scanning
    CellScanProgress {
        cells_scanned: u64,
        cells_matched: u64,
    },
    /// Cell scanning phase complete, starting history scan
    CellScanComplete {
        stealth_cells_found: usize,
        ct_cells_found: usize,
    },
    /// Progress update during history scanning (streaming: txs_processed = checked, total_txs = found)
    HistoryScanProgress {
        txs_processed: u64,
        total_txs: u64,
    },
    /// Scan fully complete
    Complete {
        total_stealth_cells: usize,
        total_ct_cells: usize,
        total_tx_records: usize,
    },
    /// Scan failed with error
    Error(String),
}

/// Cell scanner that finds stealth cells belonging to wallet accounts.
pub struct Scanner {
    rpc: RpcClient,
    store: Store,
    config: Config,
}

/// Scan progress information.
#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub cells_scanned: u64,
    pub cells_matched: u64,
    pub current_cursor: Option<String>,
    pub is_complete: bool,
}

/// Result of a scan operation.
#[derive(Debug)]
pub struct ScanResult {
    pub stealth_cells: Vec<StealthCell>,
    pub total_capacity: u64,
    pub progress: ScanProgress,
}

/// Result for a single account from multi-account scan.
#[derive(Debug)]
pub struct AccountScanResult {
    pub account_id: u64,
    pub cells: Vec<StealthCell>,
    /// New cells found that weren't in the previous scan.
    pub new_cells: Vec<StealthCell>,
    /// Total capacity of all cells (new and existing).
    pub total_capacity: u64,
}

/// Result for CT cells from a single account scan.
#[derive(Debug)]
pub struct AccountCtScanResult {
    pub account_id: u64,
    pub cells: Vec<CtCell>,
    /// New CT cells found that weren't in the previous scan.
    pub new_cells: Vec<CtCell>,
    /// Aggregated balances by token type.
    pub balances: Vec<CtBalance>,
}

/// Result for ct-info cells from a single account scan.
#[derive(Debug)]
pub struct AccountCtInfoScanResult {
    pub account_id: u64,
    pub cells: Vec<CtInfoCell>,
    /// New ct-info cells found that weren't in the previous scan.
    pub new_cells: Vec<CtInfoCell>,
}

/// Combined result from scanning all accounts for stealth, CT, and CT-info cells.
#[derive(Debug)]
pub struct ScanAllResult {
    pub stealth_results: Vec<AccountScanResult>,
    pub ct_results: Vec<AccountCtScanResult>,
    pub ct_info_results: Vec<AccountCtInfoScanResult>,
}

impl Scanner {
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
            .map_err(|_| color_eyre::eyre::eyre!("Invalid stealth lock code hash length"))?;
        Ok(arr)
    }

    /// Load the scan cursor from storage.
    pub fn load_cursor(&self) -> Result<Option<JsonBytes>> {
        let cursor: Option<String> = self.store.load_metadata(SCAN_CURSOR_KEY)?;
        match cursor {
            Some(s) if !s.is_empty() => {
                let bytes = hex::decode(&s)?;
                Ok(Some(JsonBytes::from_vec(bytes)))
            }
            _ => Ok(None),
        }
    }

    /// Save the scan cursor to storage.
    pub fn save_cursor(&self, cursor: Option<&JsonBytes>) -> Result<()> {
        let cursor_str = cursor
            .map(|c| hex::encode(c.as_bytes()))
            .unwrap_or_default();
        self.store.save_metadata(SCAN_CURSOR_KEY, &cursor_str)?;
        Ok(())
    }

    /// Clear the scan cursor (for full rescan).
    pub fn clear_cursor(&self) -> Result<()> {
        self.save_cursor(None)
    }

    /// Scan for stealth cells belonging to a single account.
    ///
    /// This performs a single page of scanning and returns the results.
    /// Call repeatedly until `progress.is_complete` is true.
    pub fn scan_page(&self, account: &Account) -> Result<ScanResult> {
        let code_hash = self.stealth_lock_code_hash()?;
        let cursor = self.load_cursor()?;

        let view_key = account.view_secret_key();
        let spend_pub = account.spend_public_key();

        self.scan_page_with_keys(&code_hash, &view_key, &spend_pub, cursor)
    }

    /// Scan for stealth cells using raw keys.
    fn scan_page_with_keys(
        &self,
        code_hash: &[u8; 32],
        view_key: &SecretKey,
        spend_pub: &PublicKey,
        cursor: Option<JsonBytes>,
    ) -> Result<ScanResult> {
        let result = self
            .rpc
            .get_cells_by_lock_prefix(code_hash, CELLS_PER_PAGE, cursor)?;

        let mut stealth_cells = Vec::new();
        let mut total_capacity = 0u64;
        let mut cells_scanned = 0u64;

        for cell in &result.objects {
            cells_scanned += 1;

            // Extract lock script args
            let lock_args = cell.output.lock.args.as_bytes();

            // Check if this cell belongs to us
            if matches_key(lock_args, view_key, spend_pub) {
                debug!("Found matching stealth cell: {:?}", cell.out_point);

                let capacity: u64 = cell.output.capacity.into();
                total_capacity += capacity;

                // Build OutPoint as bytes (tx_hash || index as u32 LE)
                let mut out_point_bytes = Vec::with_capacity(36);
                out_point_bytes.extend_from_slice(cell.out_point.tx_hash.as_bytes());
                out_point_bytes.extend_from_slice(&cell.out_point.index.value().to_le_bytes());

                // Validate that tx_hash is not all zeros (sanity check)
                let is_zero_hash = cell.out_point.tx_hash.as_bytes().iter().all(|&b| b == 0);
                if is_zero_hash {
                    info!(
                        "WARNING: Scanned cell has zero tx_hash! This should not happen. \
                        Lock code_hash: 0x{}, capacity: {} shannons",
                        hex::encode(cell.output.lock.code_hash.as_bytes()),
                        capacity
                    );
                }

                stealth_cells.push(StealthCell::new(
                    out_point_bytes,
                    capacity,
                    lock_args.to_vec(),
                ));
            }
        }

        // Determine if we're done
        let is_complete = result.last_cursor.is_empty();
        let next_cursor = if is_complete {
            None
        } else {
            Some(result.last_cursor.clone())
        };

        // Save cursor for next call
        self.save_cursor(next_cursor.as_ref())?;

        let progress = ScanProgress {
            cells_scanned,
            cells_matched: stealth_cells.len() as u64,
            current_cursor: next_cursor.map(|c| hex::encode(c.as_bytes())),
            is_complete,
        };

        Ok(ScanResult {
            stealth_cells,
            total_capacity,
            progress,
        })
    }

    /// Perform a full scan for an account (all pages).
    ///
    /// This will scan all stealth cells on the chain and return those
    /// belonging to the account. Use `scan_page` for incremental scanning.
    pub fn full_scan(&self, account: &Account) -> Result<ScanResult> {
        info!("Starting full scan for account: {}", account.name);

        // Clear any existing cursor for a fresh start
        self.clear_cursor()?;

        let code_hash = self.stealth_lock_code_hash()?;
        let view_key = account.view_secret_key();
        let spend_pub = account.spend_public_key();

        let mut all_cells = Vec::new();
        let mut total_capacity = 0u64;
        let mut total_scanned = 0u64;

        loop {
            let cursor = self.load_cursor()?;
            let result = self.scan_page_with_keys(&code_hash, &view_key, &spend_pub, cursor)?;

            total_scanned += result.progress.cells_scanned;
            total_capacity += result.total_capacity;
            all_cells.extend(result.stealth_cells);

            if result.progress.is_complete {
                break;
            }
        }

        info!(
            "Full scan complete: {} cells scanned, {} matched, {} CKB total",
            total_scanned,
            all_cells.len(),
            total_capacity as f64 / 100_000_000.0
        );

        let cells_matched = all_cells.len() as u64;
        Ok(ScanResult {
            stealth_cells: all_cells,
            total_capacity,
            progress: ScanProgress {
                cells_scanned: total_scanned,
                cells_matched,
                current_cursor: None,
                is_complete: true,
            },
        })
    }

    /// Scan for stealth cells belonging to multiple accounts.
    ///
    /// Returns a Vec of AccountScanResult with both existing and new cells.
    /// Also persists found cells and transaction records to the store.
    pub fn scan_all_accounts(&self, accounts: &[Account]) -> Result<Vec<AccountScanResult>> {
        if accounts.is_empty() {
            return Ok(Vec::new());
        }

        info!("Starting scan for {} accounts", accounts.len());

        // Clear cursor for fresh scan
        self.clear_cursor()?;

        let code_hash = self.stealth_lock_code_hash()?;

        // Log the code_hash being used for debugging
        let is_zero_code_hash = code_hash.iter().all(|&b| b == 0);
        if is_zero_code_hash {
            info!(
                "WARNING: Scanning with all-zero stealth_lock_code_hash! \
                This is likely a config issue. Please update your devnet config \
                with the actual deployed contract code_hash."
            );
        } else {
            debug!(
                "Scanning with stealth_lock_code_hash: 0x{}",
                hex::encode(code_hash)
            );
        }

        // Load existing cells for each account to detect new ones
        let mut existing_out_points: std::collections::HashMap<
            u64,
            std::collections::HashSet<Vec<u8>>,
        > = std::collections::HashMap::new();
        for account in accounts {
            let cells = self.store.get_stealth_cells(account.id)?;
            let out_points: std::collections::HashSet<_> =
                cells.iter().map(|c| c.out_point.clone()).collect();
            existing_out_points.insert(account.id, out_points);
        }

        // Prepare keys for all accounts
        let account_keys: Vec<_> = accounts
            .iter()
            .map(|a| (a.id, a.view_secret_key(), a.spend_public_key()))
            .collect();

        let mut results: Vec<AccountScanResult> = accounts
            .iter()
            .map(|a| AccountScanResult {
                account_id: a.id,
                cells: Vec::new(),
                new_cells: Vec::new(),
                total_capacity: 0,
            })
            .collect();
        let mut total_scanned = 0u64;

        loop {
            let cursor = self.load_cursor()?;
            let cells_result =
                self.rpc
                    .get_cells_by_lock_prefix(&code_hash, CELLS_PER_PAGE, cursor)?;

            for cell in &cells_result.objects {
                total_scanned += 1;
                let lock_args = cell.output.lock.args.as_bytes();

                // Check against all accounts
                for (account_id, view_key, spend_pub) in &account_keys {
                    if matches_key(lock_args, view_key, spend_pub) {
                        let capacity: u64 = cell.output.capacity.into();

                        let mut out_point_bytes = Vec::with_capacity(36);
                        out_point_bytes.extend_from_slice(cell.out_point.tx_hash.as_bytes());
                        out_point_bytes
                            .extend_from_slice(&cell.out_point.index.value().to_le_bytes());

                        // Validate that tx_hash is not all zeros (sanity check)
                        let is_zero_hash =
                            cell.out_point.tx_hash.as_bytes().iter().all(|&b| b == 0);
                        if is_zero_hash {
                            info!(
                                "WARNING: scan_all_accounts found cell with zero tx_hash! \
                                Account {}, capacity: {} shannons, lock code_hash: 0x{}",
                                account_id,
                                capacity,
                                hex::encode(cell.output.lock.code_hash.as_bytes())
                            );
                        }

                        let stealth_cell =
                            StealthCell::new(out_point_bytes.clone(), capacity, lock_args.to_vec());

                        // Find the account's result
                        if let Some(result) =
                            results.iter_mut().find(|r| r.account_id == *account_id)
                        {
                            result.total_capacity += capacity;
                            result.cells.push(stealth_cell.clone());

                            // Check if this is a new cell
                            let is_new = existing_out_points
                                .get(account_id)
                                .map(|set| !set.contains(&out_point_bytes))
                                .unwrap_or(true);

                            if is_new {
                                result.new_cells.push(stealth_cell);
                            }
                        }

                        // A cell can only belong to one account, so break
                        break;
                    }
                }
            }

            // Check if done
            if cells_result.last_cursor.is_empty() {
                break;
            }

            // Save cursor
            self.save_cursor(Some(&cells_result.last_cursor))?;
        }

        // Persist cells and transaction records to store
        for result in &results {
            // Save all cells
            if let Err(e) = self
                .store
                .save_stealth_cells(result.account_id, &result.cells)
            {
                info!(
                    "Failed to save cells for account {}: {}",
                    result.account_id, e
                );
            }

            // Note: Transaction history is now derived from on-chain data
            // using scan_tx_history(), not recorded during cell scanning.
        }

        info!(
            "Multi-account scan complete: {} cells scanned",
            total_scanned
        );

        Ok(results)
    }

    /// Get the current tip block number.
    pub fn get_tip_block_number(&self) -> Result<u64> {
        self.rpc.get_tip_block_number()
    }

    /// Get a reference to the RPC client.
    pub fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    // ==================== CT Cell Scanning ====================

    /// Get the CT token type code hash as bytes.
    fn ct_token_code_hash(&self) -> Result<Option<[u8; 32]>> {
        let hash_str = self
            .config
            .contracts
            .ct_token_code_hash
            .trim_start_matches("0x");

        // Check if it's all zeros (not configured)
        if hash_str.chars().all(|c| c == '0') {
            return Ok(None);
        }

        let bytes = hex::decode(hash_str)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| color_eyre::eyre::eyre!("Invalid CT token code hash length"))?;
        Ok(Some(arr))
    }

    /// Check if a cell has a CT token type script.
    fn is_ct_cell(&self, cell: &ckb_sdk::rpc::ckb_indexer::Cell) -> bool {
        if let Some(type_script) = &cell.output.type_
            && let Ok(Some(ct_code_hash)) = self.ct_token_code_hash()
        {
            return type_script.code_hash.as_bytes() == ct_code_hash;
        }
        false
    }

    /// Extract CT cell data from output_data.
    ///
    /// Expected format:
    /// - commitment: 32 bytes (Pedersen commitment)
    /// - encrypted_amount: 32 bytes
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

    /// Derive shared secret for CT amount decryption.
    fn derive_ct_shared_secret(lock_args: &[u8], view_key: &SecretKey) -> Option<[u8; 32]> {
        // Use the stealth module's derive_shared_secret which does proper ECDH
        derive_shared_secret(lock_args, view_key)
    }

    /// Scan for CT cells belonging to multiple accounts.
    ///
    /// This scans all cells with stealth-lock that also have ct-token-type,
    /// then decrypts the amounts for matching accounts.
    pub fn scan_ct_cells(&self, accounts: &[Account]) -> Result<Vec<AccountCtScanResult>> {
        // Check if CT is configured
        let ct_code_hash = match self.ct_token_code_hash()? {
            Some(hash) => hash,
            None => {
                info!("CT token not configured, skipping CT scan");
                return Ok(accounts
                    .iter()
                    .map(|a| AccountCtScanResult {
                        account_id: a.id,
                        cells: Vec::new(),
                        new_cells: Vec::new(),
                        balances: Vec::new(),
                    })
                    .collect());
            }
        };

        info!(
            "Starting CT scan for {} accounts, ct_code_hash: {}",
            accounts.len(),
            hex::encode(ct_code_hash)
        );

        let stealth_code_hash = self.stealth_lock_code_hash()?;

        // Load existing CT cells for each account to detect new ones
        let mut existing_out_points: std::collections::HashMap<
            u64,
            std::collections::HashSet<Vec<u8>>,
        > = std::collections::HashMap::new();
        for account in accounts {
            let cells = self.store.get_ct_cells(account.id)?;
            let out_points: std::collections::HashSet<_> =
                cells.iter().map(|c| c.out_point.clone()).collect();
            existing_out_points.insert(account.id, out_points);
        }

        // Prepare keys for all accounts
        let account_keys: Vec<_> = accounts
            .iter()
            .map(|a| (a.id, a.view_secret_key(), a.spend_public_key()))
            .collect();

        let mut results: Vec<AccountCtScanResult> = accounts
            .iter()
            .map(|a| AccountCtScanResult {
                account_id: a.id,
                cells: Vec::new(),
                new_cells: Vec::new(),
                balances: Vec::new(),
            })
            .collect();

        // Clear cursor for fresh scan
        self.clear_cursor()?;

        let mut total_scanned = 0u64;

        loop {
            let cursor = self.load_cursor()?;
            let cells_result =
                self.rpc
                    .get_cells_by_lock_prefix(&stealth_code_hash, CELLS_PER_PAGE, cursor)?;

            for cell in &cells_result.objects {
                total_scanned += 1;

                // Check if this cell has CT token type
                if !self.is_ct_cell(cell) {
                    continue;
                }

                let lock_args = cell.output.lock.args.as_bytes();

                // Check against all accounts for lock ownership
                for (account_id, view_key, spend_pub) in &account_keys {
                    if !matches_key(lock_args, view_key, spend_pub) {
                        continue;
                    }

                    // This CT cell belongs to this account
                    debug!("Found matching CT cell: {:?}", cell.out_point);

                    // Parse cell data
                    let cell_data = cell
                        .output_data
                        .as_ref()
                        .map(|d| d.as_bytes())
                        .unwrap_or(&[]);
                    let (commitment, encrypted_amount) = match Self::parse_ct_cell_data(cell_data) {
                        Some(data) => data,
                        None => {
                            debug!("Invalid CT cell data format");
                            continue;
                        }
                    };

                    // Derive shared secret and decrypt amount
                    let shared_secret = match Self::derive_ct_shared_secret(lock_args, view_key) {
                        Some(s) => s,
                        None => {
                            debug!("Failed to derive shared secret");
                            continue;
                        }
                    };

                    let amount = match ct::decrypt_amount(&encrypted_amount, &shared_secret) {
                        Some(a) => a,
                        None => {
                            debug!("Failed to decrypt CT amount");
                            continue;
                        }
                    };

                    // TODO: Verify commitment = amount*G + blinding*H
                    // For now, we use zero blinding factor as placeholder
                    let blinding_factor = [0u8; 32];

                    // Extract full type script args (ct_info_code_hash || token_id = 64 bytes)
                    let type_script_args: Vec<u8> = cell
                        .output
                        .type_
                        .as_ref()
                        .map(|t| t.args.as_bytes().to_vec())
                        .unwrap_or_default();

                    // Build OutPoint
                    let mut out_point_bytes = Vec::with_capacity(36);
                    out_point_bytes.extend_from_slice(cell.out_point.tx_hash.as_bytes());
                    out_point_bytes.extend_from_slice(&cell.out_point.index.value().to_le_bytes());

                    let ct_cell = CtCell::new(
                        out_point_bytes.clone(),
                        type_script_args,
                        commitment,
                        encrypted_amount,
                        blinding_factor,
                        amount,
                        lock_args.to_vec(),
                    );

                    // Find the account's result
                    if let Some(result) = results.iter_mut().find(|r| r.account_id == *account_id) {
                        result.cells.push(ct_cell.clone());

                        // Check if this is a new cell
                        let is_new = existing_out_points
                            .get(account_id)
                            .map(|set| !set.contains(&out_point_bytes))
                            .unwrap_or(true);

                        if is_new {
                            result.new_cells.push(ct_cell);
                        }
                    }

                    // A cell can only belong to one account
                    break;
                }
            }

            // Check if done
            if cells_result.last_cursor.is_empty() {
                break;
            }

            self.save_cursor(Some(&cells_result.last_cursor))?;
        }

        // Calculate balances and persist cells
        for result in &mut results {
            // Aggregate balances
            result.balances = aggregate_ct_balances(&result.cells);

            // Save all CT cells to store
            if let Err(e) = self.store.save_ct_cells(result.account_id, &result.cells) {
                info!(
                    "Failed to save CT cells for account {}: {}",
                    result.account_id, e
                );
            }

            // Note: Transaction history is now derived from on-chain data
            // using scan_tx_history(), not recorded during cell scanning.
        }

        info!(
            "CT scan complete: {} cells scanned, {} accounts processed",
            total_scanned,
            accounts.len()
        );

        Ok(results)
    }

    /// Incremental scan: resumes from the last saved cursor.
    ///
    /// Only fetches cells added since the previous scan.
    /// New cells are appended to the store via `add_*` methods.
    pub fn incremental_scan(&self, accounts: &[Account]) -> Result<ScanAllResult> {
        let cursor = self.load_cursor()?;
        info!(
            "Starting incremental scan for {} accounts (cursor: {})",
            accounts.len(),
            if cursor.is_some() {
                "resuming"
            } else {
                "from beginning"
            }
        );
        self.scan_with_cursor(accounts, cursor)
    }

    /// Full scan: clears all stored cells and scans from the beginning.
    ///
    /// Does not read the saved cursor - passes `None` to start from scratch.
    /// The first successful page will overwrite any old cursor in the store.
    pub fn full_scan_all(&self, accounts: &[Account]) -> Result<ScanAllResult> {
        info!("Starting full scan for {} accounts", accounts.len());

        // Clear the scan cursor to ensure we start fresh
        if let Err(e) = self.clear_cursor() {
            info!("Failed to clear scan cursor: {}", e);
        }

        // Clear all stored cells for each account
        for account in accounts {
            if let Err(e) = self.store.clear_all_cells_for_account(account.id) {
                info!("Failed to clear cells for account {}: {}", account.id, e);
            }
        }

        // Start from the beginning (no cursor)
        self.scan_with_cursor(accounts, None)
    }

    /// Core scan loop: fetches cells starting from `initial_cursor` and processes
    /// stealth, CT, and CT-info cells in a single pass.
    ///
    /// The cursor is saved after each page so the next call can resume.
    /// New cells are appended to existing stored cells via `add_*` methods.
    fn scan_with_cursor(
        &self,
        accounts: &[Account],
        initial_cursor: Option<JsonBytes>,
    ) -> Result<ScanAllResult> {
        if accounts.is_empty() {
            return Ok(ScanAllResult {
                stealth_results: Vec::new(),
                ct_results: Vec::new(),
                ct_info_results: Vec::new(),
            });
        }

        let stealth_code_hash = self.stealth_lock_code_hash()?;
        let ct_code_hash = self.ct_token_code_hash()?;
        let ct_info_hash = self.ct_info_code_hash()?;

        // Load existing out_points for each account to detect new cells
        let mut existing_stealth_out_points: std::collections::HashMap<
            u64,
            std::collections::HashSet<Vec<u8>>,
        > = std::collections::HashMap::new();
        let mut existing_ct_out_points: std::collections::HashMap<
            u64,
            std::collections::HashSet<Vec<u8>>,
        > = std::collections::HashMap::new();
        let mut existing_ct_info_out_points: std::collections::HashMap<
            u64,
            std::collections::HashSet<Vec<u8>>,
        > = std::collections::HashMap::new();

        for account in accounts {
            let stealth_cells = self.store.get_stealth_cells(account.id)?;
            existing_stealth_out_points.insert(
                account.id,
                stealth_cells.iter().map(|c| c.out_point.clone()).collect(),
            );

            let ct_cells = self.store.get_ct_cells(account.id)?;
            existing_ct_out_points.insert(
                account.id,
                ct_cells.iter().map(|c| c.out_point.clone()).collect(),
            );

            let ct_info_cells = self.store.get_ct_info_cells(account.id)?;
            existing_ct_info_out_points.insert(
                account.id,
                ct_info_cells.iter().map(|c| c.out_point.clone()).collect(),
            );
        }

        // Prepare keys for all accounts
        let account_keys: Vec<_> = accounts
            .iter()
            .map(|a| (a.id, a.view_secret_key(), a.spend_public_key()))
            .collect();

        // Initialize results
        let mut stealth_results: Vec<AccountScanResult> = accounts
            .iter()
            .map(|a| AccountScanResult {
                account_id: a.id,
                cells: Vec::new(),
                new_cells: Vec::new(),
                total_capacity: 0,
            })
            .collect();

        let mut ct_results: Vec<AccountCtScanResult> = accounts
            .iter()
            .map(|a| AccountCtScanResult {
                account_id: a.id,
                cells: Vec::new(),
                new_cells: Vec::new(),
                balances: Vec::new(),
            })
            .collect();

        let mut ct_info_results: Vec<AccountCtInfoScanResult> = accounts
            .iter()
            .map(|a| AccountCtInfoScanResult {
                account_id: a.id,
                cells: Vec::new(),
                new_cells: Vec::new(),
            })
            .collect();

        let mut total_scanned = 0u64;
        let mut cursor = initial_cursor;

        loop {
            let cells_result =
                self.rpc
                    .get_cells_by_lock_prefix(&stealth_code_hash, CELLS_PER_PAGE, cursor)?;

            for cell in &cells_result.objects {
                total_scanned += 1;
                let lock_args = cell.output.lock.args.as_bytes();

                // Determine cell type
                let is_ct = ct_code_hash
                    .as_ref()
                    .map(|hash| {
                        cell.output
                            .type_
                            .as_ref()
                            .map(|t| t.code_hash.as_bytes() == *hash)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);

                let is_ct_info = ct_info_hash
                    .as_ref()
                    .map(|hash| {
                        cell.output
                            .type_
                            .as_ref()
                            .map(|t| t.code_hash.as_bytes() == *hash)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);

                // Check against all accounts
                for (account_id, view_key, spend_pub) in &account_keys {
                    if !matches_key(lock_args, view_key, spend_pub) {
                        continue;
                    }

                    let mut out_point_bytes = Vec::with_capacity(36);
                    out_point_bytes.extend_from_slice(cell.out_point.tx_hash.as_bytes());
                    out_point_bytes.extend_from_slice(&cell.out_point.index.value().to_le_bytes());

                    if is_ct {
                        // Process as CT cell
                        let cell_data = cell
                            .output_data
                            .as_ref()
                            .map(|d| d.as_bytes())
                            .unwrap_or(&[]);
                        let (commitment, encrypted_amount) =
                            match Self::parse_ct_cell_data(cell_data) {
                                Some(data) => data,
                                None => {
                                    debug!("Invalid CT cell data format");
                                    break;
                                }
                            };

                        let shared_secret = match Self::derive_ct_shared_secret(lock_args, view_key)
                        {
                            Some(s) => s,
                            None => {
                                debug!("Failed to derive shared secret");
                                break;
                            }
                        };

                        let amount = match ct::decrypt_amount(&encrypted_amount, &shared_secret) {
                            Some(a) => a,
                            None => {
                                debug!("Failed to decrypt CT amount");
                                break;
                            }
                        };

                        let blinding_factor = [0u8; 32];
                        let type_script_args: Vec<u8> = cell
                            .output
                            .type_
                            .as_ref()
                            .map(|t| t.args.as_bytes().to_vec())
                            .unwrap_or_default();

                        let ct_cell = CtCell::new(
                            out_point_bytes.clone(),
                            type_script_args,
                            commitment,
                            encrypted_amount,
                            blinding_factor,
                            amount,
                            lock_args.to_vec(),
                        );

                        if let Some(result) =
                            ct_results.iter_mut().find(|r| r.account_id == *account_id)
                        {
                            let is_new = existing_ct_out_points
                                .get(account_id)
                                .map(|set| !set.contains(&out_point_bytes))
                                .unwrap_or(true);

                            result.cells.push(ct_cell.clone());
                            if is_new {
                                result.new_cells.push(ct_cell);
                            }
                        }
                    } else if is_ct_info {
                        // Process as CT-info cell
                        let cell_data = cell
                            .output_data
                            .as_ref()
                            .map(|d| d.as_bytes().to_vec())
                            .unwrap_or_default();

                        let ct_info_data = match CtInfoData::from_bytes(&cell_data) {
                            Ok(data) => {
                                // Log ct-info cell details for troubleshooting
                                tracing::debug!(
                                    "Parsed ct-info cell: total_supply={}, supply_cap={} ({}), flags=0x{:02x}",
                                    data.total_supply,
                                    data.supply_cap,
                                    if data.supply_cap == 0 {
                                        "UNLIMITED"
                                    } else {
                                        "limited"
                                    },
                                    data.flags
                                );
                                data
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Invalid ct-info cell data (len={}): {}. Raw data: 0x{}",
                                    cell_data.len(),
                                    e,
                                    hex::encode(&cell_data[..cell_data.len().min(64)])
                                );
                                break;
                            }
                        };

                        let type_args = cell
                            .output
                            .type_
                            .as_ref()
                            .map(|t| t.args.as_bytes().to_vec())
                            .unwrap_or_default();

                        if type_args.len() < 32 {
                            debug!("Invalid ct-info type args length: {}", type_args.len());
                            break;
                        }

                        let mut token_id = [0u8; 32];
                        token_id.copy_from_slice(&type_args[0..32]);

                        let capacity: u64 = cell.output.capacity.into();

                        let ct_info_cell = CtInfoCell::new(
                            out_point_bytes.clone(),
                            token_id,
                            ct_info_data.total_supply,
                            ct_info_data.supply_cap,
                            ct_info_data.flags,
                            capacity,
                            lock_args.to_vec(),
                        );

                        if let Some(result) = ct_info_results
                            .iter_mut()
                            .find(|r| r.account_id == *account_id)
                        {
                            let is_new = existing_ct_info_out_points
                                .get(account_id)
                                .map(|set| !set.contains(&out_point_bytes))
                                .unwrap_or(true);

                            result.cells.push(ct_info_cell.clone());
                            if is_new {
                                result.new_cells.push(ct_info_cell);
                            }
                        }
                    } else {
                        // Process as stealth cell (plain CKB)
                        let capacity: u64 = cell.output.capacity.into();

                        let stealth_cell =
                            StealthCell::new(out_point_bytes.clone(), capacity, lock_args.to_vec());

                        if let Some(result) = stealth_results
                            .iter_mut()
                            .find(|r| r.account_id == *account_id)
                        {
                            result.total_capacity += capacity;
                            result.cells.push(stealth_cell.clone());

                            let is_new = existing_stealth_out_points
                                .get(account_id)
                                .map(|set| !set.contains(&out_point_bytes))
                                .unwrap_or(true);

                            if is_new {
                                result.new_cells.push(stealth_cell);
                            }
                        }
                    }

                    // A cell can only belong to one account
                    break;
                }
            }

            // Check if done
            if cells_result.last_cursor.is_empty() {
                break;
            }

            // Save cursor after each page for resume capability
            self.save_cursor(Some(&cells_result.last_cursor))?;
            cursor = Some(cells_result.last_cursor);
        }

        // Persist new cells to store (incrementally) and recalculate total_capacity
        for result in &mut stealth_results {
            if !result.new_cells.is_empty() {
                if let Err(e) = self
                    .store
                    .add_stealth_cells(result.account_id, &result.new_cells)
                {
                    info!(
                        "Failed to add stealth cells for account {}: {}",
                        result.account_id, e
                    );
                }

                // Note: Transaction history is now derived from on-chain data
                // using scan_tx_history(), not recorded during cell scanning.
            }

            // Recalculate total_capacity from ALL stored cells (existing + new)
            let all_stealth_cells = self.store.get_stealth_cells(result.account_id)?;
            result.total_capacity = all_stealth_cells.iter().map(|c| c.capacity).sum();
        }

        for result in &mut ct_results {
            if !result.new_cells.is_empty() {
                if let Err(e) = self
                    .store
                    .add_ct_cells(result.account_id, &result.new_cells)
                {
                    info!(
                        "Failed to add CT cells for account {}: {}",
                        result.account_id, e
                    );
                }

                // Note: Transaction history is now derived from on-chain data
                // using scan_tx_history(), not recorded during cell scanning.
            }

            // Aggregate balances from ALL cells (existing + new)
            let all_ct_cells = self.store.get_ct_cells(result.account_id)?;
            result.balances = aggregate_ct_balances(&all_ct_cells);
        }

        for result in &ct_info_results {
            if !result.new_cells.is_empty()
                && let Err(e) = self
                    .store
                    .add_ct_info_cells(result.account_id, &result.new_cells)
            {
                info!(
                    "Failed to add ct-info cells for account {}: {}",
                    result.account_id, e
                );
            }
        }

        info!(
            "Scan complete: {} cells scanned, {} accounts processed",
            total_scanned,
            accounts.len()
        );

        Ok(ScanAllResult {
            stealth_results,
            ct_results,
            ct_info_results,
        })
    }

    // ==================== CT Info Cell Scanning ====================

    /// Get the CT info type code hash as bytes.
    fn ct_info_code_hash(&self) -> Result<Option<[u8; 32]>> {
        let hash_str = self
            .config
            .contracts
            .ct_info_code_hash
            .trim_start_matches("0x");

        // Check if it's all zeros (not configured)
        if hash_str.chars().all(|c| c == '0') {
            return Ok(None);
        }

        let bytes = hex::decode(hash_str)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| color_eyre::eyre::eyre!("Invalid CT info code hash length"))?;
        Ok(Some(arr))
    }

    /// Check if a cell has a CT info type script.
    fn is_ct_info_cell(&self, cell: &ckb_sdk::rpc::ckb_indexer::Cell) -> bool {
        if let Some(type_script) = &cell.output.type_
            && let Ok(Some(ct_info_hash)) = self.ct_info_code_hash()
        {
            return type_script.code_hash.as_bytes() == ct_info_hash;
        }
        false
    }

    /// Scan for ct-info cells belonging to multiple accounts.
    ///
    /// ct-info cells are controlled by stealth-lock, so we scan for cells
    /// where the lock matches one of our accounts.
    pub fn scan_ct_info_cells(&self, accounts: &[Account]) -> Result<Vec<AccountCtInfoScanResult>> {
        // Check if CT info is configured
        let ct_info_hash = match self.ct_info_code_hash()? {
            Some(hash) => hash,
            None => {
                info!("CT info type not configured, skipping ct-info scan");
                return Ok(accounts
                    .iter()
                    .map(|a| AccountCtInfoScanResult {
                        account_id: a.id,
                        cells: Vec::new(),
                        new_cells: Vec::new(),
                    })
                    .collect());
            }
        };

        info!(
            "Starting CT info scan for {} accounts, ct_info_hash: {}",
            accounts.len(),
            hex::encode(ct_info_hash)
        );

        let stealth_code_hash = self.stealth_lock_code_hash()?;

        // Load existing ct-info cells for each account to detect new ones
        let mut existing_out_points: std::collections::HashMap<
            u64,
            std::collections::HashSet<Vec<u8>>,
        > = std::collections::HashMap::new();
        for account in accounts {
            let cells = self.store.get_ct_info_cells(account.id)?;
            let out_points: std::collections::HashSet<_> =
                cells.iter().map(|c| c.out_point.clone()).collect();
            existing_out_points.insert(account.id, out_points);
        }

        // Prepare keys for all accounts
        let account_keys: Vec<_> = accounts
            .iter()
            .map(|a| (a.id, a.view_secret_key(), a.spend_public_key()))
            .collect();

        let mut results: Vec<AccountCtInfoScanResult> = accounts
            .iter()
            .map(|a| AccountCtInfoScanResult {
                account_id: a.id,
                cells: Vec::new(),
                new_cells: Vec::new(),
            })
            .collect();

        // Clear cursor for fresh scan
        self.clear_cursor()?;

        let mut total_scanned = 0u64;

        loop {
            let cursor = self.load_cursor()?;
            let cells_result =
                self.rpc
                    .get_cells_by_lock_prefix(&stealth_code_hash, CELLS_PER_PAGE, cursor)?;

            for cell in &cells_result.objects {
                total_scanned += 1;

                // Check if this cell has CT info type
                if !self.is_ct_info_cell(cell) {
                    continue;
                }

                let lock_args = cell.output.lock.args.as_bytes();

                // Check against all accounts for lock ownership
                for (account_id, view_key, spend_pub) in &account_keys {
                    if !matches_key(lock_args, view_key, spend_pub) {
                        continue;
                    }

                    // This ct-info cell belongs to this account
                    debug!("Found matching ct-info cell: {:?}", cell.out_point);

                    // Parse cell data
                    let cell_data = cell
                        .output_data
                        .as_ref()
                        .map(|d| d.as_bytes().to_vec())
                        .unwrap_or_default();

                    let ct_info_data = match CtInfoData::from_bytes(&cell_data) {
                        Ok(data) => {
                            tracing::debug!(
                                "Parsed ct-info cell: total_supply={}, supply_cap={} ({}), flags=0x{:02x}",
                                data.total_supply,
                                data.supply_cap,
                                if data.supply_cap == 0 {
                                    "UNLIMITED"
                                } else {
                                    "limited"
                                },
                                data.flags
                            );
                            data
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Invalid ct-info cell data (len={}): {}. Raw data: 0x{}",
                                cell_data.len(),
                                e,
                                hex::encode(&cell_data[..cell_data.len().min(64)])
                            );
                            continue;
                        }
                    };

                    // Extract token_id from type script args
                    let type_args = cell
                        .output
                        .type_
                        .as_ref()
                        .map(|t| t.args.as_bytes().to_vec())
                        .unwrap_or_default();

                    if type_args.len() < 32 {
                        debug!("Invalid ct-info type args length: {}", type_args.len());
                        continue;
                    }

                    let mut token_id = [0u8; 32];
                    token_id.copy_from_slice(&type_args[0..32]);

                    let capacity: u64 = cell.output.capacity.into();

                    // Build OutPoint
                    let mut out_point_bytes = Vec::with_capacity(36);
                    out_point_bytes.extend_from_slice(cell.out_point.tx_hash.as_bytes());
                    out_point_bytes.extend_from_slice(&cell.out_point.index.value().to_le_bytes());

                    let ct_info_cell = CtInfoCell::new(
                        out_point_bytes.clone(),
                        token_id,
                        ct_info_data.total_supply,
                        ct_info_data.supply_cap,
                        ct_info_data.flags,
                        capacity,
                        lock_args.to_vec(),
                    );

                    // Find the account's result
                    if let Some(result) = results.iter_mut().find(|r| r.account_id == *account_id) {
                        result.cells.push(ct_info_cell.clone());

                        // Check if this is a new cell
                        let is_new = existing_out_points
                            .get(account_id)
                            .map(|set| !set.contains(&out_point_bytes))
                            .unwrap_or(true);

                        if is_new {
                            result.new_cells.push(ct_info_cell);
                        }
                    }

                    // A cell can only belong to one account
                    break;
                }
            }

            // Check if done
            if cells_result.last_cursor.is_empty() {
                break;
            }

            self.save_cursor(Some(&cells_result.last_cursor))?;
        }

        // Persist ct-info cells to store
        for result in &results {
            if let Err(e) = self
                .store
                .save_ct_info_cells(result.account_id, &result.cells)
            {
                info!(
                    "Failed to save ct-info cells for account {}: {}",
                    result.account_id, e
                );
            }
        }

        info!(
            "CT info scan complete: {} cells scanned, {} accounts processed",
            total_scanned,
            accounts.len()
        );

        Ok(results)
    }

    // ==================== Transaction History Scanning ====================

    /// Scan transaction history for an account by analyzing ALL stealth-lock transactions.
    ///
    /// This method performs a complete scan that will find transactions even after
    /// cells have been spent, by:
    /// 1. Fetching all transactions involving stealth-lock cells (via indexer)
    /// 2. For each transaction, checking BOTH outputs AND inputs for ownership
    /// 3. Recording tx_hash in persistent index so we never lose track of spent cells
    /// 4. Calculating delta for each relevant transaction
    ///
    /// This processes transactions in batches, checking ALL accounts in a single pass
    /// to avoid redundant scanning. Uses a shared cursor for all accounts.
    pub fn scan_tx_history_all(
        &self,
        accounts: &[Account],
        update_tx: Option<&tokio::sync::mpsc::UnboundedSender<ScanUpdate>>,
    ) -> Result<usize> {
        if accounts.is_empty() {
            return Ok(0);
        }

        info!(
            "Full transaction history scan for {} accounts",
            accounts.len()
        );

        let stealth_code_hash = self.stealth_lock_code_hash()?;

        // Prepare per-account data
        struct AccountData {
            id: u64,
            view_key: SecretKey,
            spend_pub: PublicKey,
            records: Vec<TxRecord>,
            processed_tx_hashes: HashSet<[u8; 32]>,
            spent_out_points: Vec<Vec<u8>>, // OutPoints of cells spent by this account
        }

        let mut account_data: Vec<AccountData> = accounts
            .iter()
            .map(|account| {
                let records = self.store.get_tx_history(account.id).unwrap_or_default();
                let processed_tx_hashes: HashSet<[u8; 32]> =
                    records.iter().map(|r| r.tx_hash).collect();
                AccountData {
                    id: account.id,
                    view_key: account.view_secret_key(),
                    spend_pub: account.spend_public_key(),
                    records,
                    processed_tx_hashes,
                    spent_out_points: Vec::new(),
                }
            })
            .collect();

        // Load shared cursor for resumable scanning (stored as hex string)
        let cursor_key = "history_scan_cursor".to_string();
        let cursor_hex: Option<String> = self.store.load_metadata(&cursor_key).unwrap_or(None);
        let mut cursor: Option<JsonBytes> = cursor_hex
            .clone()
            .filter(|s| !s.is_empty())
            .and_then(|s| hex::decode(&s).ok())
            .map(JsonBytes::from_vec);

        let mut txs_scanned: u64 = 0;
        let mut total_records_found: usize = 0;
        let mut block_timestamps: HashMap<u64, i64> = HashMap::new();

        if cursor.is_some() {
            info!(
                "Scanning stealth-lock transactions (incremental, resuming from saved cursor)..."
            );
        } else {
            info!("Scanning stealth-lock transactions (full scan, no cursor)...");
        }

        loop {
            let txs_result = self.rpc.get_transactions_by_lock_prefix(
                &stealth_code_hash,
                100, // batch size
                cursor.clone(),
            )?;

            let mut tx_cache: HashMap<[u8; 32], ckb_jsonrpc_types::TransactionView> = HashMap::new();
            let mut batch_has_new_records = false;

            for tx_obj in &txs_result.objects {
                let tx_hash_h256 = match tx_obj {
                    ckb_sdk::rpc::ckb_indexer::Tx::Ungrouped(tx) => tx.tx_hash.clone(),
                    ckb_sdk::rpc::ckb_indexer::Tx::Grouped(grouped) => grouped.tx_hash.clone(),
                };

                let mut tx_hash_bytes = [0u8; 32];
                tx_hash_bytes.copy_from_slice(tx_hash_h256.as_bytes());

                txs_scanned += 1;

                // Check if ALL accounts have already processed this tx
                let all_processed = account_data
                    .iter()
                    .all(|ad| ad.processed_tx_hashes.contains(&tx_hash_bytes));
                if all_processed {
                    continue;
                }

                // Fetch the full transaction
                let tx_with_status = match self.rpc.get_transaction(tx_hash_h256.clone())? {
                    Some(tx) => tx,
                    None => continue,
                };

                // Skip if not committed
                if tx_with_status.tx_status.status != ckb_jsonrpc_types::Status::Committed {
                    continue;
                }

                let tx_view = match &tx_with_status.transaction {
                    Some(response_format) => match &response_format.inner {
                        Either::Left(tx) => tx.clone(),
                        Either::Right(_) => continue,
                    },
                    _ => continue,
                };

                // Get block info (shared across accounts)
                let (block_number, timestamp) = match &tx_with_status.tx_status.block_number {
                    Some(n) => {
                        let bn: u64 = (*n).into();
                        let ts = self.get_block_timestamp(bn, &mut block_timestamps)?;
                        (bn, ts)
                    }
                    None => continue,
                };

                // Check each account
                for ad in &mut account_data {
                    // Skip if this account already processed this tx
                    if ad.processed_tx_hashes.contains(&tx_hash_bytes) {
                        continue;
                    }

                    // Check if this transaction involves this account and collect spent out_points
                    let (involves_account, spent_points) = self.tx_involves_account_with_spent(
                        &tx_view.inner,
                        &ad.view_key,
                        &ad.spend_pub,
                        &stealth_code_hash,
                        &mut tx_cache,
                    )?;

                    if involves_account {
                        // Cache for delta calculation
                        tx_cache.insert(tx_hash_bytes, tx_view.clone());

                        // Collect spent out_points for later removal from store
                        ad.spent_out_points.extend(spent_points);

                        // Check if this is a genesis transaction (creates ct-info cell)
                        if let Some(token_id) = self.detect_genesis_for_account(
                            &tx_view.inner,
                            &ad.view_key,
                            &ad.spend_pub,
                        )? {
                            let record = TxRecord::ct_genesis(
                                tx_hash_bytes,
                                token_id,
                                timestamp,
                                block_number,
                            );
                            ad.records.push(record);
                            total_records_found += 1;
                            batch_has_new_records = true;
                        }

                        // Calculate CKB delta for this account
                        let ckb_delta = self.calculate_ckb_delta_cached(
                            &tx_view.inner,
                            &ad.view_key,
                            &ad.spend_pub,
                            &mut tx_cache,
                        )?;

                        // Record CKB delta if non-zero
                        if ckb_delta != 0 {
                            let record =
                                TxRecord::ckb(tx_hash_bytes, ckb_delta, timestamp, block_number);
                            ad.records.push(record);
                            total_records_found += 1;
                            batch_has_new_records = true;
                        }

                        // Calculate CT token deltas for this account
                        let ct_deltas = self.calculate_ct_deltas_cached(
                            &tx_view.inner,
                            &tx_view.inner.outputs_data,
                            &ad.view_key,
                            &ad.spend_pub,
                            &mut tx_cache,
                        )?;

                        // Record CT deltas for each token
                        for (token_id, ct_delta) in ct_deltas {
                            if ct_delta != 0 {
                                let record = TxRecord::ct(
                                    tx_hash_bytes,
                                    token_id,
                                    ct_delta,
                                    timestamp,
                                    block_number,
                                );
                                ad.records.push(record);
                                total_records_found += 1;
                                batch_has_new_records = true;
                            }
                        }

                        ad.processed_tx_hashes.insert(tx_hash_bytes);
                    }
                }
            }

            // If we found records in this batch, save them for all accounts
            if batch_has_new_records {
                for ad in &mut account_data {
                    ad.records.sort_by(|a, b| {
                        b.block_number
                            .cmp(&a.block_number)
                            .then_with(|| b.timestamp.cmp(&a.timestamp))
                    });
                    self.store.save_tx_history(ad.id, &ad.records)?;
                }
            }

            // Send progress update after each batch
            if let Some(tx) = update_tx {
                let _ = tx.send(ScanUpdate::HistoryScanProgress {
                    txs_processed: txs_scanned,
                    total_txs: total_records_found as u64,
                });
            }

            // Save cursor for resumable scanning (as hex string)
            // We save cursor BEFORE checking if done, so the next incremental scan
            // starts from where we left off (checking for new transactions)
            if !txs_result.last_cursor.is_empty() {
                cursor = Some(txs_result.last_cursor.clone());
                let cursor_hex = hex::encode(txs_result.last_cursor.as_bytes());
                self.store.save_metadata(&cursor_key, &Some(cursor_hex))?;
            }

            // Check if done - empty results means no more transactions after cursor
            if txs_result.objects.is_empty() {
                info!("History scan complete, no more transactions to check");
                break;
            }
        }

        // Remove spent cells from store for each account
        for ad in &account_data {
            if !ad.spent_out_points.is_empty() {
                info!(
                    "Removing {} spent cells for account {}",
                    ad.spent_out_points.len(),
                    ad.id
                );

                // Remove from stealth cells
                if let Err(e) = self.store.remove_spent_cells(ad.id, &ad.spent_out_points) {
                    info!("Failed to remove spent stealth cells: {}", e);
                }

                // Remove from CT cells
                if let Err(e) = self.store.remove_spent_ct_cells(ad.id, &ad.spent_out_points) {
                    info!("Failed to remove spent CT cells: {}", e);
                }

                // Remove from ct-info cells
                if let Err(e) = self.store.remove_spent_ct_info_cells(ad.id, &ad.spent_out_points) {
                    info!("Failed to remove spent ct-info cells: {}", e);
                }
            }
        }

        info!(
            "Transaction history scan complete: {} total records for {} accounts",
            total_records_found,
            accounts.len()
        );

        Ok(total_records_found)
    }

    /// Incremental scan that uses cursor for resumable scanning.
    /// This is now just a wrapper around scan_tx_history_all.
    pub fn scan_tx_history(&self, account: &Account) -> Result<Vec<TxRecord>> {
        self.scan_tx_history_all(&[account.clone()], None)?;
        self.store.get_tx_history(account.id)
    }

    /// Check if a transaction involves an account (as sender or receiver).
    /// Also returns the out_points of cells that were spent by this account.
    fn tx_involves_account_with_spent(
        &self,
        tx: &ckb_jsonrpc_types::Transaction,
        view_key: &SecretKey,
        spend_pub: &PublicKey,
        stealth_code_hash: &[u8],
        tx_cache: &mut HashMap<[u8; 32], ckb_jsonrpc_types::TransactionView>,
    ) -> Result<(bool, Vec<Vec<u8>>)> {
        let mut involves = false;
        let mut spent_out_points: Vec<Vec<u8>> = Vec::new();

        // Check outputs (receiving)
        for output in &tx.outputs {
            if output.lock.code_hash.as_bytes() == stealth_code_hash {
                let lock_args = output.lock.args.as_bytes();
                if matches_key(lock_args, view_key, spend_pub) {
                    involves = true;
                    break;
                }
            }
        }

        // Check inputs (spending) - collect spent out_points
        for input in &tx.inputs {
            let prev_tx_hash_h256 = input.previous_output.tx_hash.clone();
            let prev_index: u32 = input.previous_output.index.into();

            let mut prev_tx_hash = [0u8; 32];
            prev_tx_hash.copy_from_slice(prev_tx_hash_h256.as_bytes());

            // Get the previous transaction
            let prev_tx_view = if let Some(cached) = tx_cache.get(&prev_tx_hash) {
                cached.clone()
            } else {
                let prev_tx = match self.rpc.get_transaction(prev_tx_hash_h256.clone())? {
                    Some(tx) => tx,
                    None => continue,
                };

                let tv = match &prev_tx.transaction {
                    Some(response_format) => match &response_format.inner {
                        Either::Left(tx) => tx.clone(),
                        Either::Right(_) => continue,
                    },
                    _ => continue,
                };

                tx_cache.insert(prev_tx_hash, tv.clone());
                tv
            };

            // Check if the spent output was ours
            if let Some(prev_output) = prev_tx_view.inner.outputs.get(prev_index as usize) {
                if prev_output.lock.code_hash.as_bytes() == stealth_code_hash {
                    let lock_args = prev_output.lock.args.as_bytes();
                    if matches_key(lock_args, view_key, spend_pub) {
                        involves = true;

                        // Build the out_point (tx_hash || index_le)
                        let mut out_point = Vec::with_capacity(36);
                        out_point.extend_from_slice(prev_tx_hash_h256.as_bytes());
                        out_point.extend_from_slice(&prev_index.to_le_bytes());
                        spent_out_points.push(out_point);
                    }
                }
            }
        }

        Ok((involves, spent_out_points))
    }

    /// Get block timestamp, using cache to avoid redundant RPC calls.
    fn get_block_timestamp(
        &self,
        block_number: u64,
        cache: &mut HashMap<u64, i64>,
    ) -> Result<i64> {
        if let Some(&ts) = cache.get(&block_number) {
            return Ok(ts);
        }

        let timestamp = match self.rpc.get_block_header(block_number)? {
            Some(header) => {
                let ts_millis: u64 = header.inner.timestamp.into();
                (ts_millis / 1000) as i64 // Convert milliseconds to seconds
            }
            None => 0, // Fallback if header not found
        };

        cache.insert(block_number, timestamp);
        Ok(timestamp)
    }

    /// Calculate CKB balance change (delta) for an account in a transaction.
    /// Uses a transaction cache to reduce RPC calls.
    ///
    /// Returns: Σ(my outputs capacity) - Σ(my inputs capacity)
    fn calculate_ckb_delta_cached(
        &self,
        tx: &ckb_jsonrpc_types::Transaction,
        view_key: &SecretKey,
        spend_pub: &PublicKey,
        tx_cache: &mut HashMap<[u8; 32], ckb_jsonrpc_types::TransactionView>,
    ) -> Result<i64> {
        let stealth_code_hash = self.stealth_lock_code_hash()?;

        // Calculate output sum (cells we receive)
        let mut output_sum: u64 = 0;
        for output in &tx.outputs {
            // Check if this output uses stealth-lock
            if output.lock.code_hash.as_bytes() != stealth_code_hash {
                continue;
            }

            // Check if this output belongs to us
            let lock_args = output.lock.args.as_bytes();
            if matches_key(lock_args, view_key, spend_pub) {
                // Skip CT cells for pure CKB delta calculation
                if output.type_.is_some() {
                    continue;
                }
                let capacity: u64 = output.capacity.into();
                output_sum += capacity;
            }
        }

        // Calculate input sum (cells we spend)
        let mut input_sum: u64 = 0;
        for input in &tx.inputs {
            let prev_tx_hash_h256 = input.previous_output.tx_hash.clone();
            let prev_index: u32 = input.previous_output.index.into();

            let mut prev_tx_hash = [0u8; 32];
            prev_tx_hash.copy_from_slice(prev_tx_hash_h256.as_bytes());

            // Try to get from cache first
            let prev_tx_view = if let Some(cached) = tx_cache.get(&prev_tx_hash) {
                cached.clone()
            } else {
                // Fetch the previous transaction
                let prev_tx = match self.rpc.get_transaction(prev_tx_hash_h256)? {
                    Some(tx) => tx,
                    None => continue,
                };

                let tx_view = match &prev_tx.transaction {
                    Some(response_format) => match &response_format.inner {
                        Either::Left(tx) => tx.clone(),
                        Either::Right(_) => continue,
                    },
                    _ => continue,
                };

                // Cache it
                tx_cache.insert(prev_tx_hash, tx_view.clone());
                tx_view
            };

            // Get the output being spent
            let prev_output = match prev_tx_view.inner.outputs.get(prev_index as usize) {
                Some(o) => o,
                None => continue,
            };

            // Check if this input was ours
            if prev_output.lock.code_hash.as_bytes() != stealth_code_hash {
                continue;
            }

            let lock_args = prev_output.lock.args.as_bytes();
            if matches_key(lock_args, view_key, spend_pub) {
                // Skip CT cells for pure CKB delta calculation
                if prev_output.type_.is_some() {
                    continue;
                }
                let capacity: u64 = prev_output.capacity.into();
                input_sum += capacity;
            }
        }

        // Delta = what we received - what we spent
        let delta = output_sum as i64 - input_sum as i64;

        debug!(
            "TX delta: outputs={} - inputs={} = {}",
            output_sum, input_sum, delta
        );

        Ok(delta)
    }

    /// Calculate CT token balance changes for an account in a transaction.
    /// Returns a map of token_id -> delta for all CT tokens involved.
    ///
    /// For each token: delta = Σ(my outputs amount) - Σ(my inputs amount)
    fn calculate_ct_deltas_cached(
        &self,
        tx: &ckb_jsonrpc_types::Transaction,
        outputs_data: &[ckb_jsonrpc_types::JsonBytes],
        view_key: &SecretKey,
        spend_pub: &PublicKey,
        tx_cache: &mut HashMap<[u8; 32], ckb_jsonrpc_types::TransactionView>,
    ) -> Result<HashMap<[u8; 32], i64>> {
        let stealth_code_hash = self.stealth_lock_code_hash()?;
        let ct_code_hash = match self.ct_token_code_hash()? {
            Some(hash) => hash,
            None => return Ok(HashMap::new()), // CT not configured
        };

        let mut deltas: HashMap<[u8; 32], i64> = HashMap::new();

        // Calculate output amounts (tokens we receive)
        for (i, output) in tx.outputs.iter().enumerate() {
            // Must have CT token type script
            let type_script = match &output.type_ {
                Some(ts) if ts.code_hash.as_bytes() == ct_code_hash => ts,
                _ => continue,
            };

            // Must use stealth-lock and belong to us
            if output.lock.code_hash.as_bytes() != stealth_code_hash {
                continue;
            }
            let lock_args = output.lock.args.as_bytes();
            if !matches_key(lock_args, view_key, spend_pub) {
                continue;
            }

            // Extract token_id from type args (last 32 bytes)
            // Type args format: ct_info_code_hash (32) || token_id (32)
            let type_args = type_script.args.as_bytes();
            if type_args.len() < 32 {
                continue;
            }
            let mut token_id = [0u8; 32];
            let start = type_args.len() - 32;
            token_id.copy_from_slice(&type_args[start..]);

            // Decrypt the amount from output_data
            if let Some(output_data) = outputs_data.get(i) {
                if let Some((_, encrypted_amount)) = Self::parse_ct_cell_data(output_data.as_bytes()) {
                    if let Some(shared_secret) = Self::derive_ct_shared_secret(lock_args, view_key) {
                        if let Some(amount) = crate::domain::ct::decrypt_amount(&encrypted_amount, &shared_secret) {
                            *deltas.entry(token_id).or_insert(0) += amount as i64;
                        }
                    }
                }
            }
        }

        // Calculate input amounts (tokens we spend)
        for input in &tx.inputs {
            let prev_tx_hash_h256 = input.previous_output.tx_hash.clone();
            let prev_index: u32 = input.previous_output.index.into();

            let mut prev_tx_hash = [0u8; 32];
            prev_tx_hash.copy_from_slice(prev_tx_hash_h256.as_bytes());

            // Get previous transaction from cache or fetch
            let prev_tx_view = if let Some(cached) = tx_cache.get(&prev_tx_hash) {
                cached.clone()
            } else {
                let prev_tx = match self.rpc.get_transaction(prev_tx_hash_h256)? {
                    Some(tx) => tx,
                    None => continue,
                };

                let tx_view = match &prev_tx.transaction {
                    Some(response_format) => match &response_format.inner {
                        Either::Left(tx) => tx.clone(),
                        Either::Right(_) => continue,
                    },
                    _ => continue,
                };

                tx_cache.insert(prev_tx_hash, tx_view.clone());
                tx_view
            };

            // Get the output being spent
            let prev_output = match prev_tx_view.inner.outputs.get(prev_index as usize) {
                Some(o) => o,
                None => continue,
            };

            // Must have CT token type script
            let type_script = match &prev_output.type_ {
                Some(ts) if ts.code_hash.as_bytes() == ct_code_hash => ts,
                _ => continue,
            };

            // Must use stealth-lock and belong to us
            if prev_output.lock.code_hash.as_bytes() != stealth_code_hash {
                continue;
            }
            let lock_args = prev_output.lock.args.as_bytes();
            if !matches_key(lock_args, view_key, spend_pub) {
                continue;
            }

            // Extract token_id from type args (last 32 bytes)
            // Type args format: ct_info_code_hash (32) || token_id (32)
            let type_args = type_script.args.as_bytes();
            if type_args.len() < 32 {
                continue;
            }
            let mut token_id = [0u8; 32];
            let start = type_args.len() - 32;
            token_id.copy_from_slice(&type_args[start..]);

            // Decrypt the amount from output_data
            if let Some(prev_output_data) = prev_tx_view.inner.outputs_data.get(prev_index as usize) {
                if let Some((_, encrypted_amount)) = Self::parse_ct_cell_data(prev_output_data.as_bytes()) {
                    if let Some(shared_secret) = Self::derive_ct_shared_secret(lock_args, view_key) {
                        if let Some(amount) = crate::domain::ct::decrypt_amount(&encrypted_amount, &shared_secret) {
                            *deltas.entry(token_id).or_insert(0) -= amount as i64;
                        }
                    }
                }
            }
        }

        Ok(deltas)
    }

    /// Check if a transaction creates a ct-info cell belonging to an account (genesis).
    /// Returns Some(token_id) if this is a genesis transaction for this account.
    fn detect_genesis_for_account(
        &self,
        tx: &ckb_jsonrpc_types::Transaction,
        view_key: &SecretKey,
        spend_pub: &PublicKey,
    ) -> Result<Option<[u8; 32]>> {
        let stealth_code_hash = self.stealth_lock_code_hash()?;
        let ct_info_code_hash = match self.ct_info_code_hash()? {
            Some(hash) => hash,
            None => return Ok(None), // CT info not configured
        };

        // Check outputs for ct-info cells belonging to this account
        for output in &tx.outputs {
            // Must have ct-info type script
            let type_script = match &output.type_ {
                Some(ts) if ts.code_hash.as_bytes() == ct_info_code_hash => ts,
                _ => continue,
            };

            // Must use stealth-lock and belong to us
            if output.lock.code_hash.as_bytes() != stealth_code_hash {
                continue;
            }
            let lock_args = output.lock.args.as_bytes();
            if !matches_key(lock_args, view_key, spend_pub) {
                continue;
            }

            // Extract token_id from type args (first 32 bytes)
            let type_args = type_script.args.as_bytes();
            if type_args.len() >= 32 {
                let mut token_id = [0u8; 32];
                token_id.copy_from_slice(&type_args[0..32]);
                return Ok(Some(token_id));
            }
        }

        Ok(None)
    }

    /// Perform full rescan of tx history for all accounts (clears data first).
    pub fn scan_tx_history_full_rescan(
        &self,
        accounts: &[Account],
        update_tx: Option<&tokio::sync::mpsc::UnboundedSender<ScanUpdate>>,
    ) -> Result<usize> {
        // Clear history data and cursor for all accounts
        for account in accounts {
            self.store.clear_tx_history_index(account.id)?;
            self.store.save_tx_history(account.id, &[])?;
        }
        // Clear shared cursor
        self.store
            .save_metadata::<Option<String>>("history_scan_cursor", &None)?;

        // Now do the full scan
        self.scan_tx_history_all(accounts, update_tx)
    }

    // ==================== Background Scanning ====================

    /// Spawn a background scan task that sends progress updates via channel.
    /// Returns immediately; results are sent through the provided sender.
    pub fn spawn_background_scan(
        config: Config,
        store: Store,
        accounts: Vec<Account>,
        is_full_rescan: bool,
        update_tx: tokio::sync::mpsc::UnboundedSender<ScanUpdate>,
    ) {
        tokio::spawn(async move {
            // Send started notification
            let _ = update_tx.send(ScanUpdate::Started { is_full_rescan });

            // Clone for use after spawn_blocking
            let update_tx_complete = update_tx.clone();

            // Run the blocking scan in a separate thread
            let result = tokio::task::spawn_blocking(move || {
                let scanner = Scanner::new(config, store);
                scanner.run_scan_with_updates(&accounts, is_full_rescan, &update_tx)
            })
            .await;

            match result {
                Ok(Ok((stealth_count, ct_count, tx_count))) => {
                    let _ = update_tx_complete.send(ScanUpdate::Complete {
                        total_stealth_cells: stealth_count,
                        total_ct_cells: ct_count,
                        total_tx_records: tx_count,
                    });
                }
                Ok(Err(e)) => {
                    let _ = update_tx_complete.send(ScanUpdate::Error(e.to_string()));
                }
                Err(e) => {
                    let _ = update_tx_complete.send(ScanUpdate::Error(format!("Task panicked: {}", e)));
                }
            }
        });
    }

    /// Run the full scan process with progress updates.
    /// This is a blocking operation that should be run in a separate thread.
    fn run_scan_with_updates(
        &self,
        accounts: &[Account],
        is_full_rescan: bool,
        tx: &tokio::sync::mpsc::UnboundedSender<ScanUpdate>,
    ) -> Result<(usize, usize, usize)> {
        // Phase 1: Cell scanning
        let scan_result = if is_full_rescan {
            // Clear all data first
            for account in accounts {
                self.store.clear_all_cells_for_account(account.id)?;
            }
            self.clear_cursor()?;
            self.full_scan_all(accounts)?
        } else {
            self.incremental_scan(accounts)?
        };

        // Count results
        let mut total_stealth = 0;
        let mut total_ct = 0;

        for result in &scan_result.stealth_results {
            total_stealth += result.cells.len();
            // Save cells to store
            if !result.new_cells.is_empty() {
                self.store
                    .add_stealth_cells(result.account_id, &result.new_cells)?;
            }
        }

        for result in &scan_result.ct_results {
            total_ct += result.cells.len();
            if !result.new_cells.is_empty() {
                self.store
                    .add_ct_cells(result.account_id, &result.new_cells)?;
            }
        }

        for result in &scan_result.ct_info_results {
            if !result.new_cells.is_empty() {
                self.store
                    .add_ct_info_cells(result.account_id, &result.new_cells)?;
            }
        }

        // Send cell scan complete
        let _ = tx.send(ScanUpdate::CellScanComplete {
            stealth_cells_found: total_stealth,
            ct_cells_found: total_ct,
        });

        // Phase 2: Transaction history scanning (single pass for all accounts)
        let total_tx_records = if is_full_rescan {
            self.scan_tx_history_full_rescan(accounts, Some(tx))?
        } else {
            self.scan_tx_history_all(accounts, Some(tx))?
        };

        Ok((total_stealth, total_ct, total_tx_records))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_progress() {
        let progress = ScanProgress {
            cells_scanned: 100,
            cells_matched: 5,
            current_cursor: Some("abc123".to_string()),
            is_complete: false,
        };

        assert_eq!(progress.cells_scanned, 100);
        assert_eq!(progress.cells_matched, 5);
        assert!(!progress.is_complete);
    }
}
