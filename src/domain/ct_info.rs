//! CT Info cell data structures for confidential token minting.
//!
//! The ct-info-type cell manages token issuance and supply tracking.

use color_eyre::eyre::{eyre, Result};
use serde::{Deserialize, Serialize};

/// Flag indicating the token is mintable.
pub const MINTABLE: u8 = 0x01;
/// Flag indicating the token is burnable (future).
pub const BURNABLE: u8 = 0x02;
/// Flag indicating the token is pausable (future).
pub const PAUSABLE: u8 = 0x04;

/// CT Info cell data size in bytes.
pub const CT_INFO_DATA_SIZE: usize = 57;

/// CT Info cell data structure.
///
/// Layout (57 bytes):
/// - total_supply: u128 (16 bytes, little-endian) [0..16]
/// - supply_cap: u128 (16 bytes, little-endian) [16..32]
/// - reserved: [u8; 24] [32..56]
/// - flags: u8 [56]
///
/// Note: Authorization for minting is controlled by the ct-info cell's lock script,
/// not by this type script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtInfoData {
    /// Current total supply of tokens.
    pub total_supply: u128,
    /// Maximum supply (0 = unlimited).
    pub supply_cap: u128,
    /// Reserved for future use.
    pub reserved: [u8; 24],
    /// Flags (MINTABLE, BURNABLE, PAUSABLE).
    pub flags: u8,
}

impl CtInfoData {
    /// Create a new CtInfoData for token genesis.
    pub fn new(total_supply: u128, supply_cap: u128, flags: u8) -> Self {
        Self {
            total_supply,
            supply_cap,
            reserved: [0u8; 24],
            flags,
        }
    }

    /// Parse CtInfoData from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != CT_INFO_DATA_SIZE {
            return Err(eyre!(
                "Invalid ct-info data length: {} (expected {})",
                data.len(),
                CT_INFO_DATA_SIZE
            ));
        }

        let total_supply = u128::from_le_bytes(data[0..16].try_into().unwrap());
        let supply_cap = u128::from_le_bytes(data[16..32].try_into().unwrap());
        let mut reserved = [0u8; 24];
        reserved.copy_from_slice(&data[32..56]);
        let flags = data[56];

        Ok(Self {
            total_supply,
            supply_cap,
            reserved,
            flags,
        })
    }

    /// Serialize CtInfoData to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(CT_INFO_DATA_SIZE);
        data.extend_from_slice(&self.total_supply.to_le_bytes());
        data.extend_from_slice(&self.supply_cap.to_le_bytes());
        data.extend_from_slice(&self.reserved);
        data.push(self.flags);
        data
    }

    /// Check if minting is enabled.
    pub fn is_mintable(&self) -> bool {
        self.flags & MINTABLE != 0
    }

    /// Check if the supply cap would be exceeded.
    pub fn would_exceed_cap(&self, mint_amount: u128) -> bool {
        if self.supply_cap == 0 {
            return false; // Unlimited supply
        }
        self.total_supply.saturating_add(mint_amount) > self.supply_cap
    }

    /// Create a copy with updated supply after minting.
    pub fn with_minted(&self, mint_amount: u128) -> Result<Self> {
        if !self.is_mintable() {
            return Err(eyre!("Token is not mintable"));
        }
        if self.would_exceed_cap(mint_amount) {
            return Err(eyre!(
                "Mint would exceed supply cap: {} + {} > {}",
                self.total_supply,
                mint_amount,
                self.supply_cap
            ));
        }

        let new_supply = self
            .total_supply
            .checked_add(mint_amount)
            .ok_or_else(|| eyre!("Supply overflow"))?;

        Ok(Self {
            total_supply: new_supply,
            supply_cap: self.supply_cap,
            reserved: self.reserved,
            flags: self.flags,
        })
    }
}

/// CT Info type script args (33 bytes).
///
/// Layout:
/// - token_id: [u8; 32] - Unique token identifier
/// - version: u8 - Protocol version (0 for v1)
#[derive(Debug, Clone)]
pub struct CtInfoArgs {
    pub token_id: [u8; 32],
    pub version: u8,
}

impl CtInfoArgs {
    pub fn new(token_id: [u8; 32], version: u8) -> Self {
        Self { token_id, version }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != 33 {
            return Err(eyre!(
                "Invalid ct-info args length: {} (expected 33)",
                data.len()
            ));
        }

        let mut token_id = [0u8; 32];
        token_id.copy_from_slice(&data[0..32]);
        let version = data[32];

        Ok(Self { token_id, version })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(33);
        data.extend_from_slice(&self.token_id);
        data.push(self.version);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_info_data_roundtrip() {
        let data = CtInfoData::new(1000, 1_000_000, MINTABLE);

        let bytes = data.to_bytes();
        assert_eq!(bytes.len(), CT_INFO_DATA_SIZE);

        let parsed = CtInfoData::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.total_supply, 1000);
        assert_eq!(parsed.supply_cap, 1_000_000);
        assert_eq!(parsed.flags, MINTABLE);
        assert!(parsed.is_mintable());
    }

    #[test]
    fn test_ct_info_mint() {
        let data = CtInfoData::new(0, 1000, MINTABLE);

        // Mint 100 tokens
        let minted = data.with_minted(100).unwrap();
        assert_eq!(minted.total_supply, 100);

        // Mint 900 more (reach cap)
        let minted2 = minted.with_minted(900).unwrap();
        assert_eq!(minted2.total_supply, 1000);

        // Try to mint more (should fail)
        assert!(minted2.with_minted(1).is_err());
    }

    #[test]
    fn test_ct_info_args_roundtrip() {
        let token_id = [1u8; 32];
        let args = CtInfoArgs::new(token_id, 0);

        let bytes = args.to_bytes();
        assert_eq!(bytes.len(), 33);

        let parsed = CtInfoArgs::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.token_id, token_id);
        assert_eq!(parsed.version, 0);
    }
}
