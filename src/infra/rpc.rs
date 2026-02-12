use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::{
    rpc::ckb_indexer::{Order, ScriptType, SearchKey, SearchMode, Tx},
    CkbRpcClient,
};
use color_eyre::eyre::{eyre, Result};
use tracing::{debug, warn};

use std::time::Instant;

use crate::config::Config;

/// CKB RPC client wrapper.
pub struct RpcClient {
    client: CkbRpcClient,
    config: Config,
}

impl RpcClient {
    pub fn new(config: Config) -> Self {
        let client = CkbRpcClient::new(&config.network.rpc_url);
        Self { client, config }
    }

    /// Get the current tip block number.
    pub fn get_tip_block_number(&self) -> Result<u64> {
        let tip = self.client.get_tip_header()?;
        Ok(tip.inner.number.into())
    }

    /// Search for cells with a given lock script (using prefix search).
    pub fn get_cells_by_lock_prefix(
        &self,
        code_hash: &[u8; 32],
        limit: u32,
        after_cursor: Option<JsonBytes>,
    ) -> Result<ckb_sdk::rpc::ckb_indexer::Pagination<ckb_sdk::rpc::ckb_indexer::Cell>> {
        let start = Instant::now();
        debug!(
            "indexer.get_cells start (url={}, limit={}, has_cursor={})",
            self.config.network.rpc_url,
            limit,
            after_cursor.is_some()
        );
        let script = ckb_jsonrpc_types::Script {
            code_hash: ckb_types::H256::from_slice(code_hash)?,
            hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
            args: JsonBytes::default(), // Empty args for prefix search
        };

        let search_key = SearchKey {
            script,
            script_type: ScriptType::Lock,
            script_search_mode: Some(SearchMode::Prefix),
            filter: None,
            with_data: Some(true),
            group_by_transaction: None,
        };

        let result = self
            .client
            .get_cells(search_key, Order::Asc, limit.into(), after_cursor);

        match result {
            Ok(result) => {
                debug!(
                    "indexer.get_cells ok in {:?} (url={})",
                    start.elapsed(),
                    self.config.network.rpc_url
                );
                Ok(result)
            }
            Err(e) => {
                warn!(
                    "indexer.get_cells failed after {:?} (url={}): {}",
                    start.elapsed(),
                    self.config.network.rpc_url,
                    e
                );
                Err(eyre!("indexer.get_cells failed: {}", e))
            }
        }
    }

    /// Search for transactions with a given lock script (using prefix search).
    /// Returns transactions where the script appears in inputs or outputs.
    pub fn get_transactions_by_lock_prefix(
        &self,
        code_hash: &[u8; 32],
        limit: u32,
        after_cursor: Option<JsonBytes>,
    ) -> Result<ckb_sdk::rpc::ckb_indexer::Pagination<Tx>> {
        let start = Instant::now();
        debug!(
            "indexer.get_transactions start (url={}, limit={}, has_cursor={})",
            self.config.network.rpc_url,
            limit,
            after_cursor.is_some()
        );
        let script = ckb_jsonrpc_types::Script {
            code_hash: ckb_types::H256::from_slice(code_hash)?,
            hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
            args: JsonBytes::default(), // Empty args for prefix search
        };

        let search_key = SearchKey {
            script,
            script_type: ScriptType::Lock,
            script_search_mode: Some(SearchMode::Prefix),
            filter: None,
            with_data: Some(false),
            group_by_transaction: Some(false), // Ungrouped for better performance
        };

        let result =
            self.client
                .get_transactions(search_key, Order::Desc, limit.into(), after_cursor);

        match result {
            Ok(result) => {
                debug!(
                    "indexer.get_transactions ok in {:?} (url={})",
                    start.elapsed(),
                    self.config.network.rpc_url
                );
                Ok(result)
            }
            Err(e) => {
                warn!(
                    "indexer.get_transactions failed after {:?} (url={}): {}",
                    start.elapsed(),
                    self.config.network.rpc_url,
                    e
                );
                Err(eyre!("indexer.get_transactions failed: {}", e))
            }
        }
    }

    /// Get transaction by hash.
    pub fn get_transaction(
        &self,
        tx_hash: ckb_types::H256,
    ) -> Result<Option<ckb_jsonrpc_types::TransactionWithStatusResponse>> {
        let result = self.client.get_transaction(tx_hash)?;
        Ok(result)
    }

    /// Send a transaction.
    pub fn send_transaction(&self, tx: ckb_jsonrpc_types::Transaction) -> Result<ckb_types::H256> {
        let hash = self.client.send_transaction(tx, None)?;
        Ok(hash)
    }

    /// Get the RPC URL.
    pub fn rpc_url(&self) -> &str {
        &self.config.network.rpc_url
    }

    /// Get block header by block number.
    pub fn get_block_header(
        &self,
        block_number: u64,
    ) -> Result<Option<ckb_jsonrpc_types::HeaderView>> {
        let result = self.client.get_header_by_number(block_number.into())?;
        Ok(result)
    }

    /// Get a block by block number (JSON format).
    pub fn get_block(&self, block_number: u64) -> Result<Option<ckb_jsonrpc_types::BlockView>> {
        let result = self.client.get_block_by_number(block_number.into())?;
        Ok(result)
    }

    /// Get a packed block by block number (more efficient than JSON).
    ///
    /// This uses get_packed_block_by_number RPC which returns packed bytes,
    /// significantly reducing network transfer compared to JSON.
    pub fn get_packed_block(&self, block_number: u64) -> Result<Option<ckb_types::packed::Block>> {
        use ckb_types::prelude::*;

        let result = self
            .client
            .get_packed_block_by_number(block_number.into())?;

        match result {
            Some(json_bytes) => {
                let bytes = json_bytes.as_bytes();
                let packed_block = ckb_types::packed::Block::from_slice(bytes)
                    .map_err(|e| eyre!("Failed to parse packed block: {}", e))?;
                Ok(Some(packed_block))
            }
            None => Ok(None),
        }
    }

    /// Get the config.
    pub fn config(&self) -> &Config {
        &self.config
    }
}
