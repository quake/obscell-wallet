use ckb_jsonrpc_types::JsonBytes;
use ckb_sdk::{
    CkbRpcClient,
    rpc::ckb_indexer::{Order, ScriptType, SearchKey, SearchMode},
};
use color_eyre::eyre::Result;

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
            .get_cells(search_key, Order::Asc, limit.into(), after_cursor)?;

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
}
