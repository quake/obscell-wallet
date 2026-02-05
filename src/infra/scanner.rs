//! Cell scanning service for stealth address detection.
//!
//! Scans the CKB blockchain for cells that belong to the wallet's accounts
//! using the stealth address protocol.

use ckb_jsonrpc_types::JsonBytes;
use color_eyre::eyre::Result;
use secp256k1::{PublicKey, SecretKey};
use tracing::{debug, info};

use crate::{
    config::Config,
    domain::{account::Account, cell::StealthCell, stealth::matches_key},
    infra::{rpc::RpcClient, store::Store},
};

/// Scan cursor stored in LMDB for resuming scans.
const SCAN_CURSOR_KEY: &str = "scan_cursor";

/// Number of cells to fetch per RPC call.
const CELLS_PER_PAGE: u32 = 100;

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
    /// Returns a Vec of (account_id, Vec<StealthCell>) tuples.
    pub fn scan_all_accounts(&self, accounts: &[Account]) -> Result<Vec<(u64, Vec<StealthCell>)>> {
        if accounts.is_empty() {
            return Ok(Vec::new());
        }

        info!("Starting scan for {} accounts", accounts.len());

        // Clear cursor for fresh scan
        self.clear_cursor()?;

        let code_hash = self.stealth_lock_code_hash()?;

        // Prepare keys for all accounts
        let account_keys: Vec<_> = accounts
            .iter()
            .map(|a| (a.id, a.view_secret_key(), a.spend_public_key()))
            .collect();

        let mut results: Vec<(u64, Vec<StealthCell>)> =
            accounts.iter().map(|a| (a.id, Vec::new())).collect();
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

                        let stealth_cell =
                            StealthCell::new(out_point_bytes, capacity, lock_args.to_vec());

                        // Find the account's result vector
                        if let Some((_, cells)) =
                            results.iter_mut().find(|(id, _)| id == account_id)
                        {
                            cells.push(stealth_cell);
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
