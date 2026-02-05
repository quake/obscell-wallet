//! DevNet management for integration tests.
//!
//! Handles starting, stopping, and detecting the CKB devnet process.

use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ckb_jsonrpc_types::BlockNumber;
use ckb_sdk::CkbRpcClient;

/// DevNet manager for controlling the CKB devnet process.
pub struct DevNet {
    /// CKB process handle (if we started it)
    process: Option<Child>,
    /// Path to the devnet directory
    devnet_dir: PathBuf,
    /// RPC URL
    rpc_url: String,
    /// RPC client
    client: CkbRpcClient,
}

impl DevNet {
    /// RPC URL for the devnet
    pub const RPC_URL: &'static str = "http://127.0.0.1:8114";

    /// Create a new DevNet manager.
    pub fn new() -> Self {
        let devnet_dir = Self::devnet_dir();
        let client = CkbRpcClient::new(Self::RPC_URL);

        Self {
            process: None,
            devnet_dir,
            rpc_url: Self::RPC_URL.to_string(),
            client,
        }
    }

    /// Get the devnet directory path.
    pub fn devnet_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("devnet")
    }

    /// Get the CKB binary path.
    fn ckb_binary() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("ckb")
    }

    /// Check if the devnet RPC is reachable.
    pub fn is_running(&self) -> bool {
        TcpStream::connect_timeout(&"127.0.0.1:8114".parse().unwrap(), Duration::from_secs(1))
            .is_ok()
    }

    /// Start the devnet if not already running.
    pub fn start(&mut self) -> Result<(), String> {
        if self.is_running() {
            println!("DevNet already running at {}", self.rpc_url);
            return Ok(());
        }

        println!("Starting DevNet...");

        // Check if ckb binary exists
        let ckb_bin = Self::ckb_binary();
        if !ckb_bin.exists() {
            return Err(format!("CKB binary not found at {:?}", ckb_bin));
        }

        // Check if devnet config exists
        let config_path = self.devnet_dir.join("ckb.toml");
        if !config_path.exists() {
            return Err(format!("DevNet config not found at {:?}", config_path));
        }

        // Start CKB process
        let child = Command::new(&ckb_bin)
            .arg("run")
            .arg("-C")
            .arg(&self.devnet_dir)
            .arg("--indexer")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to start CKB: {}", e))?;

        self.process = Some(child);

        // Wait for RPC to be ready by polling
        let max_wait = Duration::from_secs(30);
        let poll_interval = Duration::from_millis(500);
        let start = std::time::Instant::now();

        while start.elapsed() < max_wait {
            if self.is_running() {
                println!("DevNet started at {}", self.rpc_url);
                // Wait a bit more for the node to be fully ready
                std::thread::sleep(Duration::from_millis(500));
                return Ok(());
            }
            std::thread::sleep(poll_interval);
        }

        // If we get here, startup failed
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
        }
        Err("CKB failed to start - RPC not reachable after 30 seconds".to_string())
    }

    /// Stop the devnet process.
    pub fn stop(&mut self) {
        if let Some(mut child) = self.process.take() {
            println!("Stopping DevNet...");
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Get the RPC client.
    pub fn client(&self) -> &CkbRpcClient {
        &self.client
    }

    /// Get the RPC URL.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    /// Get the current tip block number.
    pub fn get_tip_block_number(&self) -> Result<u64, String> {
        self.client
            .get_tip_block_number()
            .map(|n| n.value())
            .map_err(|e| format!("Failed to get tip block number: {}", e))
    }

    /// Generate a new block (IntegrationTest RPC).
    pub fn generate_block(&self) -> Result<ckb_types::H256, String> {
        self.client
            .generate_block()
            .map_err(|e| format!("Failed to generate block: {}", e))
    }

    /// Generate multiple blocks.
    pub fn generate_blocks(&self, count: u64) -> Result<(), String> {
        for _ in 0..count {
            self.generate_block()?;
        }
        Ok(())
    }

    /// Truncate the chain to a specific block number (IntegrationTest RPC).
    pub fn truncate(&self, target_tip_number: u64) -> Result<(), String> {
        // Get the block hash at the target height
        let block_hash = self
            .client
            .get_block_hash(BlockNumber::from(target_tip_number))
            .map_err(|e| format!("Failed to get block hash at {}: {}", target_tip_number, e))?
            .ok_or_else(|| format!("No block found at height {}", target_tip_number))?;

        self.client
            .truncate(block_hash)
            .map_err(|e| format!("Failed to truncate to block {}: {}", target_tip_number, e))
    }

    /// Get the checkpoint file path.
    fn checkpoint_file(&self) -> PathBuf {
        self.devnet_dir.join(".checkpoint")
    }

    /// Load the checkpoint (block number after contract deployment).
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
    pub fn save_checkpoint(&self, block_number: u64) -> Result<(), String> {
        let path = self.checkpoint_file();
        std::fs::write(&path, block_number.to_string())
            .map_err(|e| format!("Failed to save checkpoint: {}", e))
    }

    /// Reset to checkpoint (truncate chain).
    pub fn reset_to_checkpoint(&self) -> Result<(), String> {
        if let Some(checkpoint) = self.load_checkpoint() {
            let current_tip = self.get_tip_block_number()?;
            if current_tip > checkpoint {
                println!(
                    "Resetting chain from block {} to checkpoint {}",
                    current_tip, checkpoint
                );
                // Clear the transaction pool first
                self.clear_tx_pool()?;
                // Then truncate the chain
                self.truncate(checkpoint)?;
                // Clear tx pool multiple times - truncation may move txs back to mempool
                for _ in 0..3 {
                    self.clear_tx_pool()?;
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                // Wait longer for indexer to re-sync (it needs to handle the reorg)
                std::thread::sleep(std::time::Duration::from_millis(2000));
            }
            Ok(())
        } else {
            Err("No checkpoint found".to_string())
        }
    }

    /// Wait for the indexer to sync with the chain tip.
    pub fn wait_for_indexer_sync(&self) -> Result<(), String> {
        let max_wait = std::time::Duration::from_secs(10);
        let start = std::time::Instant::now();
        let poll_interval = std::time::Duration::from_millis(200);

        loop {
            let chain_tip = self.get_tip_block_number()?;
            let indexer_tip = self
                .client
                .get_indexer_tip()
                .map_err(|e| format!("Failed to get indexer tip: {}", e))?;

            if let Some(tip) = indexer_tip {
                let indexer_block: u64 = tip.block_number.into();
                if indexer_block >= chain_tip {
                    println!(
                        "Indexer synced: chain tip={}, indexer tip={}",
                        chain_tip, indexer_block
                    );
                    return Ok(());
                }
                println!(
                    "Waiting for indexer: chain tip={}, indexer tip={}",
                    chain_tip, indexer_block
                );
            }

            if start.elapsed() > max_wait {
                return Err("Timeout waiting for indexer to sync".to_string());
            }

            std::thread::sleep(poll_interval);
        }
    }

    /// Clear the transaction pool.
    pub fn clear_tx_pool(&self) -> Result<(), String> {
        self.client
            .clear_tx_pool()
            .map_err(|e| format!("Failed to clear tx pool: {}", e))
    }

    /// Clear all devnet data (for fresh start).
    pub fn clear_data(&self) -> Result<(), String> {
        let data_dir = self.devnet_dir.join("data");
        if data_dir.exists() {
            std::fs::remove_dir_all(&data_dir)
                .map_err(|e| format!("Failed to clear data directory: {}", e))?;
        }

        let checkpoint_file = self.checkpoint_file();
        if checkpoint_file.exists() {
            std::fs::remove_file(&checkpoint_file)
                .map_err(|e| format!("Failed to remove checkpoint file: {}", e))?;
        }

        Ok(())
    }
}

impl Drop for DevNet {
    fn drop(&mut self) {
        // Note: We don't stop the process on drop to allow reuse across tests
        // The process will be killed when the test binary exits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_devnet_paths() {
        let devnet = DevNet::new();
        assert!(devnet.devnet_dir.ends_with("tests/fixtures/devnet"));
    }
}
