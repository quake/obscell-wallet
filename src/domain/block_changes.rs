//! Block changes tracking for reorg undo support.
//!
//! Tracks changes made to cells and tx history in each block,
//! allowing us to undo these changes when a reorg is detected.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::cell::{CtCell, CtInfoCell, StealthCell, TxRecord};

/// Changes made to an account's state in a single block.
/// Used for undoing changes when a reorg is detected.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountBlockChanges {
    /// New stealth cells created in this block (out_point -> cell).
    /// On undo: remove these cells.
    pub new_stealth_cells: HashMap<Vec<u8>, StealthCell>,

    /// New CT cells created in this block (out_point -> cell).
    /// On undo: remove these cells.
    pub new_ct_cells: HashMap<Vec<u8>, CtCell>,

    /// New CT-info cells created in this block (out_point -> cell).
    /// On undo: remove these cells.
    pub new_ct_info_cells: HashMap<Vec<u8>, CtInfoCell>,

    /// Stealth cells spent in this block (out_point -> original cell).
    /// On undo: restore these cells.
    pub spent_stealth_cells: HashMap<Vec<u8>, StealthCell>,

    /// CT cells spent in this block (out_point -> original cell).
    /// On undo: restore these cells.
    pub spent_ct_cells: HashMap<Vec<u8>, CtCell>,

    /// CT-info cells spent/updated in this block (out_point -> original cell).
    /// On undo: restore these cells.
    pub spent_ct_info_cells: HashMap<Vec<u8>, CtInfoCell>,

    /// Tx records created in this block.
    /// On undo: remove records with matching tx_hash.
    pub tx_records: Vec<TxRecord>,
}

/// Changes made in a single block, indexed by account_id.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockChanges {
    /// Block number.
    pub block_number: u64,

    /// Block hash for verification.
    pub block_hash: [u8; 32],

    /// Changes per account.
    pub accounts: HashMap<u64, AccountBlockChanges>,
}

impl AccountBlockChanges {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if there are any changes.
    pub fn is_empty(&self) -> bool {
        self.new_stealth_cells.is_empty()
            && self.new_ct_cells.is_empty()
            && self.new_ct_info_cells.is_empty()
            && self.spent_stealth_cells.is_empty()
            && self.spent_ct_cells.is_empty()
            && self.spent_ct_info_cells.is_empty()
            && self.tx_records.is_empty()
    }

    /// Record a new stealth cell created in this block.
    pub fn add_new_stealth_cell(&mut self, cell: StealthCell) {
        self.new_stealth_cells.insert(cell.out_point.clone(), cell);
    }

    /// Record a new CT cell created in this block.
    pub fn add_new_ct_cell(&mut self, cell: CtCell) {
        self.new_ct_cells.insert(cell.out_point.clone(), cell);
    }

    /// Record a new CT-info cell created in this block.
    pub fn add_new_ct_info_cell(&mut self, cell: CtInfoCell) {
        self.new_ct_info_cells.insert(cell.out_point.clone(), cell);
    }

    /// Record a stealth cell spent in this block.
    pub fn add_spent_stealth_cell(&mut self, cell: StealthCell) {
        self.spent_stealth_cells
            .insert(cell.out_point.clone(), cell);
    }

    /// Record a CT cell spent in this block.
    pub fn add_spent_ct_cell(&mut self, cell: CtCell) {
        self.spent_ct_cells.insert(cell.out_point.clone(), cell);
    }

    /// Record a CT-info cell spent in this block.
    pub fn add_spent_ct_info_cell(&mut self, cell: CtInfoCell) {
        self.spent_ct_info_cells
            .insert(cell.out_point.clone(), cell);
    }

    /// Record a tx record created in this block.
    pub fn add_tx_record(&mut self, record: TxRecord) {
        self.tx_records.push(record);
    }
}

impl BlockChanges {
    pub fn new(block_number: u64, block_hash: [u8; 32]) -> Self {
        Self {
            block_number,
            block_hash,
            accounts: HashMap::new(),
        }
    }

    /// Get or create changes for an account.
    pub fn get_or_create_account(&mut self, account_id: u64) -> &mut AccountBlockChanges {
        self.accounts
            .entry(account_id)
            .or_insert_with(AccountBlockChanges::new)
    }

    /// Check if there are any changes.
    pub fn is_empty(&self) -> bool {
        self.accounts.values().all(|a| a.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_block_changes_empty() {
        let changes = AccountBlockChanges::new();
        assert!(changes.is_empty());
    }

    #[test]
    fn test_account_block_changes_add_cells() {
        let mut changes = AccountBlockChanges::new();

        let cell = StealthCell::new(vec![1, 2, 3], 1000, vec![4, 5, 6]);
        changes.add_new_stealth_cell(cell.clone());

        assert!(!changes.is_empty());
        assert_eq!(changes.new_stealth_cells.len(), 1);
        assert!(changes.new_stealth_cells.contains_key(&vec![1, 2, 3]));
    }

    #[test]
    fn test_block_changes_get_or_create_account() {
        let mut changes = BlockChanges::new(100, [0xab; 32]);

        // First access creates new entry
        let acc1 = changes.get_or_create_account(1);
        acc1.add_new_stealth_cell(StealthCell::new(vec![1], 100, vec![]));

        // Second access returns same entry
        let acc1_again = changes.get_or_create_account(1);
        assert_eq!(acc1_again.new_stealth_cells.len(), 1);

        // Different account is separate
        let acc2 = changes.get_or_create_account(2);
        assert!(acc2.is_empty());
    }
}
