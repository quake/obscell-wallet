use serde::{Deserialize, Serialize};

// ==================== Transaction History ====================

/// Transaction type for history records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TxType {
    /// Sent CKB to a stealth address.
    StealthSend {
        /// Recipient stealth address (hex encoded).
        to: String,
        /// Amount in shannons.
        amount: u64,
    },
    /// Received CKB at a stealth address.
    StealthReceive {
        /// Amount in shannons.
        amount: u64,
    },
    /// Transferred confidential tokens.
    CtTransfer {
        /// Token type script hash.
        token: [u8; 32],
        /// Amount transferred.
        amount: u64,
    },
    /// Minted confidential tokens.
    CtMint {
        /// Token type script hash.
        token: [u8; 32],
        /// Amount minted.
        amount: u64,
    },
}

/// Transaction status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TxStatus {
    /// Transaction submitted but not yet confirmed.
    Pending,
    /// Transaction confirmed on chain.
    Confirmed,
    /// Transaction failed or rejected.
    Failed,
}

/// A record of a transaction for history display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Type of transaction.
    pub tx_type: TxType,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: i64,
    /// Current status.
    pub status: TxStatus,
    /// Block number when confirmed (None if pending).
    pub block_number: Option<u64>,
}

impl TxRecord {
    /// Create a new transaction record.
    pub fn new(tx_hash: [u8; 32], tx_type: TxType, status: TxStatus) -> Self {
        Self {
            tx_hash,
            tx_type,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            status,
            block_number: None,
        }
    }

    /// Create a stealth send record.
    pub fn stealth_send(tx_hash: [u8; 32], to: String, amount: u64) -> Self {
        Self::new(
            tx_hash,
            TxType::StealthSend { to, amount },
            TxStatus::Pending,
        )
    }

    /// Create a stealth receive record.
    pub fn stealth_receive(tx_hash: [u8; 32], amount: u64) -> Self {
        Self::new(
            tx_hash,
            TxType::StealthReceive { amount },
            TxStatus::Confirmed,
        )
    }

    /// Create a CT token transfer record.
    pub fn ct_transfer(tx_hash: [u8; 32], token: [u8; 32], amount: u64) -> Self {
        Self::new(
            tx_hash,
            TxType::CtTransfer { token, amount },
            TxStatus::Pending,
        )
    }

    /// Create a CT token mint record.
    pub fn ct_mint(tx_hash: [u8; 32], token: [u8; 32], amount: u64) -> Self {
        Self::new(tx_hash, TxType::CtMint { token, amount }, TxStatus::Pending)
    }

    /// Mark as confirmed with block number.
    pub fn confirm(&mut self, block_number: u64) {
        self.status = TxStatus::Confirmed;
        self.block_number = Some(block_number);
    }

    /// Mark as failed.
    pub fn fail(&mut self) {
        self.status = TxStatus::Failed;
    }

    /// Get display-friendly tx hash (shortened).
    pub fn short_hash(&self) -> String {
        format!(
            "{}...{}",
            hex::encode(&self.tx_hash[..4]),
            hex::encode(&self.tx_hash[28..])
        )
    }

    /// Get display-friendly amount in CKB.
    pub fn amount_ckb(&self) -> Option<f64> {
        match &self.tx_type {
            TxType::StealthSend { amount, .. } => Some(*amount as f64 / 100_000_000.0),
            TxType::StealthReceive { amount } => Some(*amount as f64 / 100_000_000.0),
            TxType::CtTransfer { .. } | TxType::CtMint { .. } => None,
        }
    }

    /// Get transaction direction label.
    pub fn direction(&self) -> &'static str {
        match &self.tx_type {
            TxType::StealthSend { .. } => "Send",
            TxType::StealthReceive { .. } => "Receive",
            TxType::CtTransfer { .. } => "Transfer",
            TxType::CtMint { .. } => "Mint",
        }
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
    /// Token type script hash.
    pub token_type_hash: [u8; 32],
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
        token_type_hash: [u8; 32],
        commitment: [u8; 32],
        encrypted_amount: [u8; 32],
        blinding_factor: [u8; 32],
        amount: u64,
        lock_script_args: Vec<u8>,
    ) -> Self {
        Self {
            out_point,
            token_type_hash,
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
    /// Issuer identifier (32 bytes, for reference).
    pub issuer_pubkey: [u8; 32],
    /// Flags (MINTABLE, BURNABLE, etc.).
    pub flags: u8,
    /// Cell capacity in shannons.
    pub capacity: u64,
    /// Lock script args (stealth-lock args: eph_pub || pubkey_hash).
    pub lock_script_args: Vec<u8>,
}

impl CtInfoCell {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        out_point: Vec<u8>,
        token_id: [u8; 32],
        total_supply: u128,
        supply_cap: u128,
        issuer_pubkey: [u8; 32],
        flags: u8,
        capacity: u64,
        lock_script_args: Vec<u8>,
    ) -> Self {
        Self {
            out_point,
            token_id,
            total_supply,
            supply_cap,
            issuer_pubkey,
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
    /// Token type script hash (identifies the token).
    pub token_type_hash: [u8; 32],
    /// Human-readable token name (if known).
    pub token_name: Option<String>,
    /// Total balance (sum of all owned CtCells).
    pub total_amount: u64,
    /// Number of cells holding this token.
    pub cell_count: usize,
}

impl CtBalance {
    /// Create a new CtBalance.
    pub fn new(token_type_hash: [u8; 32], token_name: Option<String>) -> Self {
        Self {
            token_type_hash,
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
            hex::encode(&self.token_type_hash[..4]),
            hex::encode(&self.token_type_hash[28..])
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
            .entry(cell.token_type_hash)
            .or_insert_with(|| CtBalance::new(cell.token_type_hash, None));
        balance.add_cell(cell.amount);
    }

    let mut result: Vec<_> = balances.into_values().collect();
    // Sort by total amount descending
    result.sort_by(|a, b| b.total_amount.cmp(&a.total_amount));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_record_stealth_send() {
        let tx_hash = [0xab; 32];
        let to = "ckt1qrfrwcdnvssswdwpn3s9v8fp87emat306ctjwsm3nmlkjg8e".to_string();
        let amount = 100_00000000; // 100 CKB

        let record = TxRecord::stealth_send(tx_hash, to.clone(), amount);

        assert_eq!(record.tx_hash, tx_hash);
        assert_eq!(record.status, TxStatus::Pending);
        assert_eq!(record.direction(), "Send");
        assert_eq!(record.amount_ckb(), Some(100.0));

        if let TxType::StealthSend {
            to: addr,
            amount: amt,
        } = &record.tx_type
        {
            assert_eq!(addr, &to);
            assert_eq!(*amt, amount);
        } else {
            panic!("Expected StealthSend type");
        }
    }

    #[test]
    fn test_tx_record_stealth_receive() {
        let tx_hash = [0xcd; 32];
        let amount = 50_00000000; // 50 CKB

        let record = TxRecord::stealth_receive(tx_hash, amount);

        assert_eq!(record.tx_hash, tx_hash);
        assert_eq!(record.status, TxStatus::Confirmed);
        assert_eq!(record.direction(), "Receive");
        assert_eq!(record.amount_ckb(), Some(50.0));
    }

    #[test]
    fn test_tx_record_short_hash() {
        let tx_hash = [
            0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xab, 0xcd, 0xef, 0x99,
        ];

        let record = TxRecord::stealth_receive(tx_hash, 100);

        // short_hash should be first 4 bytes ... last 4 bytes
        let short = record.short_hash();
        assert!(short.starts_with("12345678"));
        assert!(short.ends_with("abcdef99"));
        assert!(short.contains("..."));
    }

    #[test]
    fn test_tx_record_confirm() {
        let tx_hash = [0xef; 32];
        let mut record = TxRecord::stealth_send(tx_hash, "addr".to_string(), 1000);

        assert_eq!(record.status, TxStatus::Pending);
        assert_eq!(record.block_number, None);

        record.confirm(12345678);

        assert_eq!(record.status, TxStatus::Confirmed);
        assert_eq!(record.block_number, Some(12345678));
    }

    #[test]
    fn test_tx_record_fail() {
        let tx_hash = [0xaa; 32];
        let mut record = TxRecord::stealth_send(tx_hash, "addr".to_string(), 1000);

        record.fail();

        assert_eq!(record.status, TxStatus::Failed);
    }
}
