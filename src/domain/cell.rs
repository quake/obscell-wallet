use serde::{Deserialize, Serialize};

// ==================== Transaction History ====================

/// Transaction type for history records.
/// Now represents net balance change (delta) rather than direction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TxType {
    /// CKB balance change.
    Ckb {
        /// Net change in shannons (positive = received, negative = sent).
        delta: i64,
    },
    /// Confidential token balance change (mint or transfer).
    Ct {
        /// Token ID (first 32 bytes of type args).
        token: [u8; 32],
        /// Net change in token amount (positive = received, negative = sent).
        delta: i64,
    },
    /// Create new token (genesis transaction).
    CtGenesis {
        /// Token ID of the newly created token.
        token: [u8; 32],
    },
}

/// Transaction status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TxStatus {
    /// Transaction confirmed on chain.
    Confirmed,
}

/// A record of a transaction for history display.
/// Records are derived from on-chain data, showing net balance changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Type of transaction (CKB or CT with delta).
    pub tx_type: TxType,
    /// Unix timestamp (seconds since epoch, from block header).
    pub timestamp: i64,
    /// Block number when confirmed.
    pub block_number: u64,
}

impl TxRecord {
    /// Create a CKB transaction record.
    pub fn ckb(tx_hash: [u8; 32], delta: i64, timestamp: i64, block_number: u64) -> Self {
        Self {
            tx_hash,
            tx_type: TxType::Ckb { delta },
            timestamp,
            block_number,
        }
    }

    /// Create a CT token transaction record.
    pub fn ct(
        tx_hash: [u8; 32],
        token: [u8; 32],
        delta: i64,
        timestamp: i64,
        block_number: u64,
    ) -> Self {
        Self {
            tx_hash,
            tx_type: TxType::Ct { token, delta },
            timestamp,
            block_number,
        }
    }

    /// Create a CT genesis (create token) transaction record.
    pub fn ct_genesis(
        tx_hash: [u8; 32],
        token: [u8; 32],
        timestamp: i64,
        block_number: u64,
    ) -> Self {
        Self {
            tx_hash,
            tx_type: TxType::CtGenesis { token },
            timestamp,
            block_number,
        }
    }

    /// Get display-friendly tx hash (shortened).
    pub fn short_hash(&self) -> String {
        format!(
            "{}...{}",
            hex::encode(&self.tx_hash[..4]),
            hex::encode(&self.tx_hash[28..])
        )
    }

    /// Get full tx hash as hex string with 0x prefix.
    pub fn full_hash(&self) -> String {
        format!("0x{}", hex::encode(&self.tx_hash))
    }

    /// Get the delta value (net change).
    pub fn delta(&self) -> i64 {
        match &self.tx_type {
            TxType::Ckb { delta } => *delta,
            TxType::Ct { delta, .. } => *delta,
            TxType::CtGenesis { .. } => 0,
        }
    }

    /// Get display-friendly delta in CKB (for CKB transactions).
    pub fn delta_ckb(&self) -> Option<f64> {
        match &self.tx_type {
            TxType::Ckb { delta } => Some(*delta as f64 / 100_000_000.0),
            TxType::Ct { .. } | TxType::CtGenesis { .. } => None,
        }
    }

    /// Get the token ID (for CT transactions).
    pub fn token_id(&self) -> Option<[u8; 32]> {
        match &self.tx_type {
            TxType::Ckb { .. } => None,
            TxType::Ct { token, .. } | TxType::CtGenesis { token } => Some(*token),
        }
    }

    /// Check if this is a CKB transaction.
    pub fn is_ckb(&self) -> bool {
        matches!(self.tx_type, TxType::Ckb { .. })
    }

    /// Check if this is a CT transaction.
    pub fn is_ct(&self) -> bool {
        matches!(self.tx_type, TxType::Ct { .. })
    }
}

// ==================== Cells ====================

/// A stealth cell (UTXO) owned by the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthCell {
    /// Transaction output point (tx_hash || index).
    pub out_point: Vec<u8>,
    /// Cell capacity in shannons.
    pub capacity: u64,
    /// Stealth script args: P (33B ephemeral pubkey) || Q' (20B pubkey hash).
    pub stealth_script_args: Vec<u8>,
}

/// A confidential token cell owned by the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtCell {
    /// Transaction output point.
    pub out_point: Vec<u8>,
    /// Token type script args (ct_info_code_hash || token_id = 64 bytes).
    /// Used for building transactions with matching type scripts.
    pub type_script_args: Vec<u8>,
    /// Token ID (last 32 bytes of type_script_args).
    /// Used for grouping and display.
    pub token_id: [u8; 32],
    /// Pedersen commitment (compressed Ristretto point).
    pub commitment: [u8; 32],
    /// Encrypted amount (encrypted with receiver's key).
    pub encrypted_amount: [u8; 32],
    /// Blinding factor for this commitment (local storage only).
    pub blinding_factor: [u8; 32],
    /// Decrypted amount (local storage only).
    pub amount: u64,
    /// Lock script args (for signing).
    pub lock_script_args: Vec<u8>,
}

impl StealthCell {
    pub fn new(out_point: Vec<u8>, capacity: u64, stealth_script_args: Vec<u8>) -> Self {
        Self {
            out_point,
            capacity,
            stealth_script_args,
        }
    }
}

impl CtCell {
    pub fn new(
        out_point: Vec<u8>,
        type_script_args: Vec<u8>,
        commitment: [u8; 32],
        encrypted_amount: [u8; 32],
        blinding_factor: [u8; 32],
        amount: u64,
        lock_script_args: Vec<u8>,
    ) -> Self {
        // Extract token_id from the last 32 bytes of type_script_args
        let token_id = if type_script_args.len() >= 32 {
            let mut id = [0u8; 32];
            let start = type_script_args.len() - 32;
            id.copy_from_slice(&type_script_args[start..]);
            id
        } else {
            [0u8; 32]
        };

        Self {
            out_point,
            type_script_args,
            token_id,
            commitment,
            encrypted_amount,
            blinding_factor,
            amount,
            lock_script_args,
        }
    }
}

/// A ct-info cell that controls token minting.
///
/// The ct-info cell is controlled by a stealth-lock, and whoever can
/// unlock it can mint new tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtInfoCell {
    /// Transaction output point (tx_hash || index as 36 bytes).
    pub out_point: Vec<u8>,
    /// Token ID (32 bytes, from type script args).
    pub token_id: [u8; 32],
    /// Current total supply.
    pub total_supply: u128,
    /// Maximum supply (0 = unlimited).
    pub supply_cap: u128,
    /// Flags (MINTABLE, BURNABLE, etc.).
    pub flags: u8,
    /// Cell capacity in shannons.
    pub capacity: u64,
    /// Lock script args (stealth-lock args: eph_pub || pubkey_hash).
    pub lock_script_args: Vec<u8>,
}

impl CtInfoCell {
    pub fn new(
        out_point: Vec<u8>,
        token_id: [u8; 32],
        total_supply: u128,
        supply_cap: u128,
        flags: u8,
        capacity: u64,
        lock_script_args: Vec<u8>,
    ) -> Self {
        Self {
            out_point,
            token_id,
            total_supply,
            supply_cap,
            flags,
            capacity,
            lock_script_args,
        }
    }

    /// Check if this token is mintable.
    pub fn is_mintable(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Check if minting would exceed the supply cap.
    pub fn would_exceed_cap(&self, mint_amount: u128) -> bool {
        if self.supply_cap == 0 {
            return false; // Unlimited supply
        }
        self.total_supply.saturating_add(mint_amount) > self.supply_cap
    }

    /// Get remaining mintable amount.
    pub fn remaining_supply(&self) -> Option<u128> {
        if self.supply_cap == 0 {
            None // Unlimited
        } else {
            Some(self.supply_cap.saturating_sub(self.total_supply))
        }
    }

    /// Get short token ID for display.
    pub fn short_token_id(&self) -> String {
        format!(
            "{}...{}",
            hex::encode(&self.token_id[..4]),
            hex::encode(&self.token_id[28..])
        )
    }
}

/// CT token balance aggregated from CtCells.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtBalance {
    /// Token ID (identifies the token).
    pub token_id: [u8; 32],
    /// Full type script args (ct_info_code_hash || token_id).
    pub type_script_args: Vec<u8>,
    /// Human-readable token name (if known).
    pub token_name: Option<String>,
    /// Total balance (sum of all owned CtCells).
    pub total_amount: u64,
    /// Number of cells holding this token.
    pub cell_count: usize,
}

impl CtBalance {
    /// Create a new CtBalance.
    pub fn new(token_id: [u8; 32], type_script_args: Vec<u8>, token_name: Option<String>) -> Self {
        Self {
            token_id,
            type_script_args,
            token_name,
            total_amount: 0,
            cell_count: 0,
        }
    }

    /// Add a cell's amount to this balance.
    pub fn add_cell(&mut self, amount: u64) {
        self.total_amount += amount;
        self.cell_count += 1;
    }

    /// Get short token hash for display.
    pub fn short_hash(&self) -> String {
        format!(
            "{}...{}",
            hex::encode(&self.token_id[..4]),
            hex::encode(&self.token_id[28..])
        )
    }

    /// Get display name (token_name or short hash).
    pub fn display_name(&self) -> String {
        self.token_name.clone().unwrap_or_else(|| self.short_hash())
    }
}

/// Aggregate CtCells into CtBalances by token type.
pub fn aggregate_ct_balances(cells: &[CtCell]) -> Vec<CtBalance> {
    use std::collections::HashMap;

    let mut balances: HashMap<[u8; 32], CtBalance> = HashMap::new();

    for cell in cells {
        let balance = balances
            .entry(cell.token_id)
            .or_insert_with(|| CtBalance::new(cell.token_id, cell.type_script_args.clone(), None));
        balance.add_cell(cell.amount);
    }

    let mut result: Vec<_> = balances.into_values().collect();
    // Sort by total amount descending
    result.sort_by(|a, b| b.total_amount.cmp(&a.total_amount));
    result
}

/// Aggregate CtCells into CtBalances, including tokens from ct-info cells (issuable tokens).
/// This ensures tokens you can mint appear in the list even if you have 0 balance.
pub fn aggregate_ct_balances_with_info(
    ct_cells: &[CtCell],
    ct_info_cells: &[CtInfoCell],
    config: &crate::config::Config,
) -> Vec<CtBalance> {
    use std::collections::HashMap;

    let mut balances: HashMap<[u8; 32], CtBalance> = HashMap::new();

    // First, add all ct-info cells (tokens you can mint) with 0 balance
    // Build the full type script args from ct_info_code_hash || token_id
    let ct_info_code_hash = config.contracts.ct_info_code_hash.trim_start_matches("0x");
    let ct_info_code_hash_bytes = hex::decode(ct_info_code_hash).unwrap_or_else(|_| vec![0u8; 32]);

    for info in ct_info_cells {
        let mut type_args = Vec::with_capacity(64);
        type_args.extend_from_slice(&ct_info_code_hash_bytes);
        type_args.extend_from_slice(&info.token_id);

        balances
            .entry(info.token_id)
            .or_insert_with(|| CtBalance::new(info.token_id, type_args, None));
    }

    // Then add actual balances from ct-token cells
    for cell in ct_cells {
        let balance = balances
            .entry(cell.token_id)
            .or_insert_with(|| CtBalance::new(cell.token_id, cell.type_script_args.clone(), None));
        balance.add_cell(cell.amount);
    }

    let mut result: Vec<_> = balances.into_values().collect();
    // Sort by total amount descending (but tokens with 0 balance still appear)
    result.sort_by(|a, b| b.total_amount.cmp(&a.total_amount));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_record_ckb_positive() {
        let tx_hash = [0xab; 32];
        let delta = 100_00000000i64; // +100 CKB (received)
        let timestamp = 1234567890;
        let block_number = 1000;

        let record = TxRecord::ckb(tx_hash, delta, timestamp, block_number);

        assert_eq!(record.tx_hash, tx_hash);
        assert_eq!(record.delta(), delta);
        assert_eq!(record.delta_ckb(), Some(100.0));
        assert!(record.is_ckb());
        assert!(!record.is_ct());
        assert_eq!(record.block_number, block_number);
    }

    #[test]
    fn test_tx_record_ckb_negative() {
        let tx_hash = [0xcd; 32];
        let delta = -50_00000000i64; // -50 CKB (sent)
        let timestamp = 1234567890;
        let block_number = 2000;

        let record = TxRecord::ckb(tx_hash, delta, timestamp, block_number);

        assert_eq!(record.delta(), delta);
        assert_eq!(record.delta_ckb(), Some(-50.0));
    }

    #[test]
    fn test_tx_record_ct() {
        let tx_hash = [0xef; 32];
        let token = [0x11; 32];
        let delta = 1000i64; // +1000 tokens (received)
        let timestamp = 1234567890;
        let block_number = 3000;

        let record = TxRecord::ct(tx_hash, token, delta, timestamp, block_number);

        assert_eq!(record.delta(), delta);
        assert_eq!(record.token_id(), Some(token));
        assert!(record.is_ct());
        assert!(!record.is_ckb());
        assert_eq!(record.delta_ckb(), None);
    }

    #[test]
    fn test_tx_record_short_hash() {
        let tx_hash = [
            0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xab, 0xcd, 0xef, 0x99,
        ];

        let record = TxRecord::ckb(tx_hash, 100, 0, 0);

        // short_hash should be first 4 bytes ... last 4 bytes
        let short = record.short_hash();
        assert!(short.starts_with("12345678"));
        assert!(short.ends_with("abcdef99"));
        assert!(short.contains("..."));
    }
}
