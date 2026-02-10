//! DevNet management for development mode.
//!
//! Handles generating blocks, checkpoints, and chain resets on local devnet.

use std::path::PathBuf;
use std::time::Duration;

use ckb_jsonrpc_types::BlockNumber;
use ckb_sdk::CkbRpcClient;
use ckb_types::H256;
use color_eyre::eyre::{Result, eyre};

/// DevNet manager for controlling a local CKB devnet.
pub struct DevNet {
    /// Path to the devnet directory (for checkpoint storage)
    devnet_dir: PathBuf,
    /// RPC URL
    rpc_url: String,
    /// RPC client
    client: CkbRpcClient,
}

impl DevNet {
    /// Default RPC URL for the devnet.
    pub const DEFAULT_RPC_URL: &'static str = "http://127.0.0.1:8114";

    /// Create a new DevNet manager.
    pub fn new(rpc_url: &str, devnet_dir: PathBuf) -> Self {
        let client = CkbRpcClient::new(rpc_url);
        Self {
            devnet_dir,
            rpc_url: rpc_url.to_string(),
            client,
        }
    }

    /// Create with default settings (uses app data directory).
    pub fn with_defaults() -> Self {
        let devnet_dir = crate::config::get_data_dir().join("devnet");
        Self::new(Self::DEFAULT_RPC_URL, devnet_dir)
    }

    /// Get the RPC URL.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Get the RPC client.
    pub fn client(&self) -> &CkbRpcClient {
        &self.client
    }

    /// Get the current tip block number.
    pub fn get_tip_block_number(&self) -> Result<u64> {
        self.client
            .get_tip_block_number()
            .map(|n| n.value())
            .map_err(|e| eyre!("Failed to get tip block number: {}", e))
    }

    /// Get the indexer tip block number.
    pub fn get_indexer_tip(&self) -> Result<Option<u64>> {
        self.client
            .get_indexer_tip()
            .map(|tip| tip.map(|t| t.block_number.into()))
            .map_err(|e| eyre!("Failed to get indexer tip: {}", e))
    }

    /// Check if indexer is synced with chain tip.
    pub fn is_indexer_synced(&self) -> Result<bool> {
        let chain_tip = self.get_tip_block_number()?;
        let indexer_tip = self.get_indexer_tip()?;
        Ok(indexer_tip.map(|t| t >= chain_tip).unwrap_or(false))
    }

    /// Generate a new block (IntegrationTest RPC).
    pub fn generate_block(&self) -> Result<H256> {
        self.client
            .generate_block()
            .map_err(|e| eyre!("Failed to generate block: {}", e))
    }

    /// Generate multiple blocks.
    pub fn generate_blocks(&self, count: u64) -> Result<()> {
        for _ in 0..count {
            self.generate_block()?;
        }
        Ok(())
    }

    /// Truncate the chain to a specific block number (IntegrationTest RPC).
    pub fn truncate(&self, target_tip_number: u64) -> Result<()> {
        let block_hash = self
            .client
            .get_block_hash(BlockNumber::from(target_tip_number))
            .map_err(|e| eyre!("Failed to get block hash at {}: {}", target_tip_number, e))?
            .ok_or_else(|| eyre!("No block found at height {}", target_tip_number))?;

        self.client
            .truncate(block_hash)
            .map_err(|e| eyre!("Failed to truncate to block {}: {}", target_tip_number, e))
    }

    /// Clear the transaction pool.
    pub fn clear_tx_pool(&self) -> Result<()> {
        self.client
            .clear_tx_pool()
            .map_err(|e| eyre!("Failed to clear tx pool: {}", e))
    }

    /// Get the checkpoint file path.
    fn checkpoint_file(&self) -> PathBuf {
        self.devnet_dir.join(".checkpoint")
    }

    /// Ensure devnet directory exists.
    fn ensure_dir(&self) -> Result<()> {
        if !self.devnet_dir.exists() {
            std::fs::create_dir_all(&self.devnet_dir)
                .map_err(|e| eyre!("Failed to create devnet dir: {}", e))?;
        }
        Ok(())
    }

    /// Load the checkpoint (block number).
    pub fn load_checkpoint(&self) -> Option<u64> {
        let path = self.checkpoint_file();
        if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| s.trim().parse().ok())
        } else {
            None
        }
    }

    /// Save the checkpoint.
    pub fn save_checkpoint(&self, block_number: u64) -> Result<()> {
        self.ensure_dir()?;
        let path = self.checkpoint_file();
        std::fs::write(&path, block_number.to_string())
            .map_err(|e| eyre!("Failed to save checkpoint: {}", e))
    }

    /// Save current tip as checkpoint.
    pub fn save_current_as_checkpoint(&self) -> Result<u64> {
        let tip = self.get_tip_block_number()?;
        self.save_checkpoint(tip)?;
        Ok(tip)
    }

    /// Reset to checkpoint (truncate chain).
    pub fn reset_to_checkpoint(&self) -> Result<()> {
        if let Some(checkpoint) = self.load_checkpoint() {
            let current_tip = self.get_tip_block_number()?;
            if current_tip > checkpoint {
                // Clear the transaction pool first
                self.clear_tx_pool()?;
                // Truncate the chain
                self.truncate(checkpoint)?;
                // Clear tx pool again after truncation
                for _ in 0..3 {
                    self.clear_tx_pool()?;
                    std::thread::sleep(Duration::from_millis(100));
                }
                // Generate blocks to ensure indexer processes rollback
                self.generate_blocks(3)?;
            }
            Ok(())
        } else {
            Err(eyre!("No checkpoint found"))
        }
    }

    /// Wait for the indexer to sync with the chain tip.
    pub fn wait_for_indexer_sync(&self, timeout_secs: u64) -> Result<()> {
        let max_wait = Duration::from_secs(timeout_secs);
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(200);

        loop {
            if self.is_indexer_synced()? {
                return Ok(());
            }

            if start.elapsed() > max_wait {
                return Err(eyre!("Timeout waiting for indexer to sync"));
            }

            std::thread::sleep(poll_interval);
        }
    }
}
