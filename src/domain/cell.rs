use serde::{Deserialize, Serialize};

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
