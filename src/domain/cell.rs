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
