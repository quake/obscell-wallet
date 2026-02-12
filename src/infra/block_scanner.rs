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
