use std::path::PathBuf;

use color_eyre::eyre::Result;
use heed::{Database, Env, EnvOpenOptions, byteorder::BE, types::*};
use serde::{Deserialize, Serialize};

use crate::{
    config::{get_data_dir, get_network_data_dir},
    domain::{
        account::Account,
        cell::{CtCell, CtInfoCell, StealthCell, TxRecord},
        scan_state::ScanState,
        wallet::WalletMeta,
    },
};

/// Key for storing the selected network preference in global store.
pub const SELECTED_NETWORK_KEY: &str = "selected_network";

/// Key for storing wallet metadata.
const WALLET_META_KEY: &str = "wallet_meta";

/// Key for storing scan state.
const SCAN_STATE_KEY: &str = "scan_state";

/// Wrapper around LMDB database for persistent storage.
#[derive(Clone)]
pub struct Store {
    env: Env,
}

impl Store {
    pub fn new(network: &str) -> Result<Self> {
        Self::with_path(get_network_data_dir(network).join("wallet.mdb"))
    }

    /// Create a global store for cross-network preferences (stored in base data dir).
    pub fn global() -> Result<Self> {
        Self::with_path(get_data_dir().join("global.mdb"))
    }

    pub fn with_path(path: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&path)?;
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(100 * 1024 * 1024) // 100MB
                .max_dbs(10)
                .open(path)?
        };
        Ok(Self { env })
    }

    /// Save an account to the database.
    pub fn save_account(&self, account: &Account) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let db: Database<U64<BE>, SerdeRmp<Account>> =
            self.env.create_database(&mut wtxn, Some("accounts"))?;
        db.put(&mut wtxn, &account.id, account)?;
        wtxn.commit()?;
        Ok(())
    }

    /// List all accounts.
    pub fn list_accounts(&self) -> Result<Vec<Account>> {
        let rtxn = self.env.read_txn()?;
        let db: Option<Database<U64<BE>, SerdeRmp<Account>>> =
            self.env.open_database(&rtxn, Some("accounts"))?;

        match db {
            Some(db) => {
                let mut accounts = Vec::new();
                for result in db.iter(&rtxn)? {
                    let (_, account) = result?;
                    accounts.push(account);
                }
                Ok(accounts)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Get an account by ID.
    pub fn get_account(&self, id: u64) -> Result<Option<Account>> {
        let rtxn = self.env.read_txn()?;
        let db: Option<Database<U64<BE>, SerdeRmp<Account>>> =
            self.env.open_database(&rtxn, Some("accounts"))?;

        match db {
            Some(db) => Ok(db.get(&rtxn, &id)?),
            None => Ok(None),
        }
    }

    /// Delete an account.
    pub fn delete_account(&self, id: u64) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let db: Database<U64<BE>, SerdeRmp<Account>> =
            self.env.create_database(&mut wtxn, Some("accounts"))?;
        db.delete(&mut wtxn, &id)?;
        wtxn.commit()?;
        Ok(())
    }

    // ==================== Wallet Metadata ====================

    /// Save wallet metadata.
    pub fn save_wallet_meta(&self, meta: &WalletMeta) -> Result<()> {
        self.save_metadata(WALLET_META_KEY, meta)
    }

    /// Load wallet metadata.
    pub fn load_wallet_meta(&self) -> Result<Option<WalletMeta>> {
        self.load_metadata(WALLET_META_KEY)
    }

    /// Check if wallet exists (has metadata).
    pub fn wallet_exists(&self) -> Result<bool> {
        Ok(self.load_wallet_meta()?.is_some())
    }

    /// Delete wallet metadata (for reset/migration).
    pub fn delete_wallet_meta(&self) -> Result<()> {
        self.delete_metadata(WALLET_META_KEY)
    }

    /// Save metadata (e.g., scan cursor).
    pub fn save_metadata<T: Serialize + 'static>(&self, key: &str, value: &T) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let db: Database<Str, SerdeRmp<T>> =
            self.env.create_database(&mut wtxn, Some("metadata"))?;
        db.put(&mut wtxn, key, value)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Load metadata.
    pub fn load_metadata<T: for<'de> Deserialize<'de> + 'static>(
        &self,
        key: &str,
    ) -> Result<Option<T>> {
        let rtxn = self.env.read_txn()?;
        let db: Option<Database<Str, SerdeRmp<T>>> =
            self.env.open_database(&rtxn, Some("metadata"))?;

        match db {
            Some(db) => Ok(db.get(&rtxn, key)?),
            None => Ok(None),
        }
    }

    // ==================== Scan State Storage ====================

    /// Save scan state.
    pub fn save_scan_state(&self, state: &ScanState) -> Result<()> {
        self.save_metadata(SCAN_STATE_KEY, state)
    }

    /// Load scan state.
    pub fn load_scan_state(&self) -> Result<ScanState> {
        Ok(self
            .load_metadata::<ScanState>(SCAN_STATE_KEY)?
            .unwrap_or_default())
    }

    /// Clear scan state (for full rescan).
    pub fn clear_scan_state(&self) -> Result<()> {
        self.save_scan_state(&ScanState::new())
    }

    // ==================== Stealth Cell Storage ====================

    /// Save stealth cells for an account (replaces existing cells).
    pub fn save_stealth_cells(&self, account_id: u64, cells: &[StealthCell]) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let db: Database<U64<BE>, SerdeRmp<Vec<StealthCell>>> =
            self.env.create_database(&mut wtxn, Some("stealth_cells"))?;
        db.put(&mut wtxn, &account_id, &cells.to_vec())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get stealth cells for an account.
    pub fn get_stealth_cells(&self, account_id: u64) -> Result<Vec<StealthCell>> {
        let rtxn = self.env.read_txn()?;
        let db: Option<Database<U64<BE>, SerdeRmp<Vec<StealthCell>>>> =
            self.env.open_database(&rtxn, Some("stealth_cells"))?;

        match db {
            Some(db) => Ok(db.get(&rtxn, &account_id)?.unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    /// Remove spent cells from an account's stored cells.
    pub fn remove_spent_cells(&self, account_id: u64, spent_out_points: &[Vec<u8>]) -> Result<()> {
        let mut cells = self.get_stealth_cells(account_id)?;
        cells.retain(|cell| !spent_out_points.contains(&cell.out_point));
        self.save_stealth_cells(account_id, &cells)?;
        Ok(())
    }

    /// Clear all stealth cells for an account.
    pub fn clear_stealth_cells(&self, account_id: u64) -> Result<()> {
        self.save_stealth_cells(account_id, &[])?;
        Ok(())
    }

    /// Add new stealth cells to an account (for incremental scan updates).
    pub fn add_stealth_cells(&self, account_id: u64, new_cells: &[StealthCell]) -> Result<()> {
        let mut cells = self.get_stealth_cells(account_id)?;

        // Avoid duplicates by checking out_point
        for new_cell in new_cells {
            if !cells.iter().any(|c| c.out_point == new_cell.out_point) {
                cells.push(new_cell.clone());
            }
        }

        self.save_stealth_cells(account_id, &cells)?;
        Ok(())
    }

    // ==================== Transaction History ====================

    /// Save a transaction record to the history.
    pub fn save_tx_record(&self, account_id: u64, record: &TxRecord) -> Result<()> {
        let mut records = self.get_tx_history(account_id)?;

        // Check if tx already exists (by hash), update if so
        if let Some(existing) = records.iter_mut().find(|r| r.tx_hash == record.tx_hash) {
            *existing = record.clone();
        } else {
            records.push(record.clone());
        }

        // Sort by timestamp descending (newest first)
        records.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        self.save_tx_history(account_id, &records)
    }

    /// Save all transaction records for an account.
    pub fn save_tx_history(&self, account_id: u64, records: &[TxRecord]) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let db: Database<U64<BE>, SerdeRmp<Vec<TxRecord>>> =
            self.env.create_database(&mut wtxn, Some("tx_history"))?;
        db.put(&mut wtxn, &account_id, &records.to_vec())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get transaction history for an account.
    pub fn get_tx_history(&self, account_id: u64) -> Result<Vec<TxRecord>> {
        let rtxn = self.env.read_txn()?;
        let db: Option<Database<U64<BE>, SerdeRmp<Vec<TxRecord>>>> =
            self.env.open_database(&rtxn, Some("tx_history"))?;

        match db {
            Some(db) => Ok(db.get(&rtxn, &account_id)?.unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    /// Get transaction history for an account with limit.
    pub fn get_tx_history_limited(&self, account_id: u64, limit: usize) -> Result<Vec<TxRecord>> {
        let records = self.get_tx_history(account_id)?;
        Ok(records.into_iter().take(limit).collect())
    }

    /// Get a transaction record by hash.
    pub fn get_tx_by_hash(&self, account_id: u64, tx_hash: &[u8; 32]) -> Result<Option<TxRecord>> {
        let records = self.get_tx_history(account_id)?;
        Ok(records.into_iter().find(|r| &r.tx_hash == tx_hash))
    }

    // ==================== TX History Index Storage ====================
    // Stores all tx_hashes that an account has ever been involved in,
    // even after cells are spent. This enables full history reconstruction on rescan.

    /// Get the set of all tx_hashes for an account's history index.
    pub fn get_tx_history_index(&self, account_id: u64) -> Result<Vec<[u8; 32]>> {
        let rtxn = self.env.read_txn()?;
        let db: Option<Database<U64<BE>, SerdeRmp<Vec<[u8; 32]>>>> =
            self.env.open_database(&rtxn, Some("tx_history_index"))?;

        match db {
            Some(db) => Ok(db.get(&rtxn, &account_id)?.unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    /// Save the tx history index for an account.
    pub fn save_tx_history_index(&self, account_id: u64, tx_hashes: &[[u8; 32]]) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let db: Database<U64<BE>, SerdeRmp<Vec<[u8; 32]>>> = self
            .env
            .create_database(&mut wtxn, Some("tx_history_index"))?;
        db.put(&mut wtxn, &account_id, &tx_hashes.to_vec())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Add tx_hashes to the history index (deduplicated).
    pub fn add_to_tx_history_index(
        &self,
        account_id: u64,
        new_tx_hashes: &[[u8; 32]],
    ) -> Result<()> {
        let mut tx_hashes = self.get_tx_history_index(account_id)?;

        for tx_hash in new_tx_hashes {
            if !tx_hashes.contains(tx_hash) {
                tx_hashes.push(*tx_hash);
            }
        }

        self.save_tx_history_index(account_id, &tx_hashes)
    }

    /// Clear the tx history index for an account.
    pub fn clear_tx_history_index(&self, account_id: u64) -> Result<()> {
        self.save_tx_history_index(account_id, &[])
    }

    // ==================== CT Cell Storage ====================

    /// Save CT cells for an account (replaces existing cells).
    pub fn save_ct_cells(&self, account_id: u64, cells: &[CtCell]) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let db: Database<U64<BE>, SerdeRmp<Vec<CtCell>>> =
            self.env.create_database(&mut wtxn, Some("ct_cells"))?;
        db.put(&mut wtxn, &account_id, &cells.to_vec())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get CT cells for an account.
    pub fn get_ct_cells(&self, account_id: u64) -> Result<Vec<CtCell>> {
        let rtxn = self.env.read_txn()?;
        let db: Option<Database<U64<BE>, SerdeRmp<Vec<CtCell>>>> =
            self.env.open_database(&rtxn, Some("ct_cells"))?;

        match db {
            Some(db) => Ok(db.get(&rtxn, &account_id)?.unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    /// Add new CT cells to an account (for incremental scan updates).
    pub fn add_ct_cells(&self, account_id: u64, new_cells: &[CtCell]) -> Result<()> {
        let mut cells = self.get_ct_cells(account_id)?;

        // Avoid duplicates by checking out_point
        for new_cell in new_cells {
            if !cells.iter().any(|c| c.out_point == new_cell.out_point) {
                cells.push(new_cell.clone());
            }
        }

        self.save_ct_cells(account_id, &cells)?;
        Ok(())
    }

    /// Remove spent CT cells from an account's stored cells.
    pub fn remove_spent_ct_cells(
        &self,
        account_id: u64,
        spent_out_points: &[Vec<u8>],
    ) -> Result<()> {
        let mut cells = self.get_ct_cells(account_id)?;
        cells.retain(|cell| !spent_out_points.contains(&cell.out_point));
        self.save_ct_cells(account_id, &cells)?;
        Ok(())
    }

    /// Clear all CT cells for an account.
    pub fn clear_ct_cells(&self, account_id: u64) -> Result<()> {
        self.save_ct_cells(account_id, &[])?;
        Ok(())
    }

    /// Get CT cells filtered by token ID.
    pub fn get_ct_cells_by_token(
        &self,
        account_id: u64,
        token_id: &[u8; 32],
    ) -> Result<Vec<CtCell>> {
        let cells = self.get_ct_cells(account_id)?;
        Ok(cells
            .into_iter()
            .filter(|c| &c.token_id == token_id)
            .collect())
    }

    // ==================== CT Info Cell Storage ====================

    /// Save ct-info cells for an account (replaces existing cells).
    pub fn save_ct_info_cells(&self, account_id: u64, cells: &[CtInfoCell]) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let db: Database<U64<BE>, SerdeRmp<Vec<CtInfoCell>>> =
            self.env.create_database(&mut wtxn, Some("ct_info_cells"))?;
        db.put(&mut wtxn, &account_id, &cells.to_vec())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Get ct-info cells for an account.
    pub fn get_ct_info_cells(&self, account_id: u64) -> Result<Vec<CtInfoCell>> {
        let rtxn = self.env.read_txn()?;
        let db: Option<Database<U64<BE>, SerdeRmp<Vec<CtInfoCell>>>> =
            self.env.open_database(&rtxn, Some("ct_info_cells"))?;

        match db {
            Some(db) => Ok(db.get(&rtxn, &account_id)?.unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    /// Add new ct-info cells to an account (for incremental scan updates).
    pub fn add_ct_info_cells(&self, account_id: u64, new_cells: &[CtInfoCell]) -> Result<()> {
        let mut cells = self.get_ct_info_cells(account_id)?;

        // Avoid duplicates by checking out_point
        for new_cell in new_cells {
            if !cells.iter().any(|c| c.out_point == new_cell.out_point) {
                cells.push(new_cell.clone());
            }
        }

        self.save_ct_info_cells(account_id, &cells)?;
        Ok(())
    }

    /// Get ct-info cell by token ID.
    pub fn get_ct_info_by_token_id(
        &self,
        account_id: u64,
        token_id: &[u8; 32],
    ) -> Result<Option<CtInfoCell>> {
        let cells = self.get_ct_info_cells(account_id)?;
        Ok(cells.into_iter().find(|c| &c.token_id == token_id))
    }

    /// Remove spent ct-info cells from an account's stored cells.
    pub fn remove_spent_ct_info_cells(
        &self,
        account_id: u64,
        spent_out_points: &[Vec<u8>],
    ) -> Result<()> {
        let mut cells = self.get_ct_info_cells(account_id)?;
        cells.retain(|cell| !spent_out_points.contains(&cell.out_point));
        self.save_ct_info_cells(account_id, &cells)?;
        Ok(())
    }

    /// Clear all ct-info cells for an account.
    pub fn clear_ct_info_cells(&self, account_id: u64) -> Result<()> {
        self.save_ct_info_cells(account_id, &[])?;
        Ok(())
    }

    /// Delete a metadata key.
    pub fn delete_metadata(&self, key: &str) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        // Try to open the metadata database; if it doesn't exist, nothing to delete
        let db: Option<Database<Str, Bytes>> = self.env.open_database(&wtxn, Some("metadata"))?;

        if let Some(db) = db {
            db.delete(&mut wtxn, key)?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Clear all cells (stealth, CT, CT-info) for an account and reset scan cursor.
    /// Used for full rescan to purge potentially corrupted data.
    pub fn clear_all_cells_for_account(&self, account_id: u64) -> Result<()> {
        self.clear_stealth_cells(account_id)?;
        self.clear_ct_cells(account_id)?;
        self.clear_ct_info_cells(account_id)?;
        self.clear_tx_history_index(account_id)?;
        self.save_tx_history(account_id, &[])?;
        Ok(())
    }

    /// Clear all data for a full rescan (scan state + all account cells).
    pub fn clear_all_for_rescan(&self, account_ids: &[u64]) -> Result<()> {
        self.clear_scan_state()?;
        for &account_id in account_ids {
            self.clear_all_cells_for_account(account_id)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_scan_state_persistence() {
        let temp_dir = tempdir().unwrap();
        let store = Store::with_path(temp_dir.path().join("test.mdb")).unwrap();

        // Create a scan state with data
        let mut state = ScanState::new();
        state.add_block(100, [1u8; 32]);
        state.add_block(101, [2u8; 32]);
        state.add_block(102, [3u8; 32]);

        // Save it
        store.save_scan_state(&state).unwrap();

        // Load it back
        let loaded = store.load_scan_state().unwrap();

        assert_eq!(loaded.last_scanned_block, Some(102));
        assert_eq!(loaded.recent_blocks.len(), 3);
        assert_eq!(loaded.next_block_to_scan(0), 103);
        assert_eq!(loaded.expected_parent_hash(), Some([3u8; 32]));
    }

    #[test]
    fn test_scan_state_empty_on_new_store() {
        let temp_dir = tempdir().unwrap();
        let store = Store::with_path(temp_dir.path().join("test.mdb")).unwrap();

        // Load from empty store
        let loaded = store.load_scan_state().unwrap();

        assert_eq!(loaded.last_scanned_block, None);
        assert!(loaded.recent_blocks.is_empty());
        assert_eq!(loaded.next_block_to_scan(50), 50); // Should use start_block
    }

    #[test]
    fn test_scan_state_survives_reopen() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.mdb");

        // Create and save state
        {
            let store = Store::with_path(db_path.clone()).unwrap();
            let mut state = ScanState::new();
            state.add_block(200, [42u8; 32]);
            store.save_scan_state(&state).unwrap();
        }

        // Reopen and verify
        {
            let store = Store::with_path(db_path).unwrap();
            let loaded = store.load_scan_state().unwrap();
            assert_eq!(loaded.last_scanned_block, Some(200));
            assert_eq!(loaded.next_block_to_scan(0), 201);
        }
    }
}
