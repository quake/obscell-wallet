//! Integration test module for obscell-wallet.
//!
//! Provides a test environment that manages:
//! - CKB devnet startup/detection
//! - Contract deployment
//! - Faucet for funding test accounts
//! - Checkpoint/rollback for test isolation

pub mod contract_deployer;
pub mod devnet;
pub mod e2e_basic_flow;
pub mod e2e_ct_flow;
pub mod e2e_ct_genesis_mint;
pub mod e2e_user_flow;
pub mod faucet;

use std::sync::OnceLock;

use ckb_types::H256;
use secp256k1::SecretKey;

use contract_deployer::{ContractDeployer, DeployedContracts};
use devnet::DevNet;
use faucet::Faucet;

static TEST_ENV: OnceLock<TestEnv> = OnceLock::new();

/// Test environment for integration tests.
pub struct TestEnv {
    /// DevNet manager.
    pub devnet: DevNet,
    /// Deployed contracts info.
    pub contracts: DeployedContracts,
    /// Faucet for funding test accounts.
    pub faucet: Faucet,
    /// Checkpoint block number (after contract deployment).
    pub checkpoint: u64,
    /// Miner secret key.
    pub miner_key: SecretKey,
    /// Miner lock args.
    pub miner_lock_args: [u8; 20],
}

impl TestEnv {
    /// Get or initialize the test environment.
    ///
    /// This is designed to be called once at the start of tests,
    /// with the environment reused across all tests.
    pub fn get() -> &'static TestEnv {
        TEST_ENV.get_or_init(|| TestEnv::setup().expect("Failed to setup test environment"))
    }

    /// Setup the test environment.
    fn setup() -> Result<Self, String> {
        println!("=== Setting up integration test environment ===");

        // Load miner key
        let (miner_key, miner_lock_args) = Faucet::load_miner_key()?;
        println!("Miner lock args: 0x{}", hex::encode(miner_lock_args));

        // Start or detect devnet
        let mut devnet = DevNet::new();
        devnet.start()?;

        // Clear any stale transactions from the pool (from previous failed runs)
        let _ = devnet.clear_tx_pool();

        // Check if we have a checkpoint (contracts already deployed)
        let (contracts, checkpoint) = if let Some(checkpoint) = devnet.load_checkpoint() {
            println!("Found checkpoint at block {}", checkpoint);

            // Load contract info
            if let Some(contracts_info) = ContractDeployer::load_deployed_info() {
                // Verify contracts are still deployed
                let deployer = ContractDeployer::new(DevNet::RPC_URL, miner_key, miner_lock_args);
                if deployer.are_all_deployed(&contracts_info)? {
                    println!("Contract still deployed, reusing existing setup");
                    (contracts_info, checkpoint)
                } else {
                    println!("Contract no longer deployed, redeploying...");
                    Self::deploy_and_checkpoint(&devnet, &miner_key, &miner_lock_args)?
                }
            } else {
                println!("No contract info found, deploying...");
                Self::deploy_and_checkpoint(&devnet, &miner_key, &miner_lock_args)?
            }
        } else {
            println!("No checkpoint found, performing fresh setup...");
            Self::deploy_and_checkpoint(&devnet, &miner_key, &miner_lock_args)?
        };

        println!(
            "Contract deployed: type_id_hash = 0x{}",
            contracts
                .stealth_lock
                .type_id_hash
                .as_ref()
                .map(|h| hex::encode(h.as_bytes()))
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "CKB-auth deployed: data_hash = 0x{}",
            hex::encode(contracts.ckb_auth.data_hash.as_bytes())
        );
        println!(
            "CT-info-type deployed: type_id_hash = 0x{}",
            contracts
                .ct_info_type
                .type_id_hash
                .as_ref()
                .map(|h| hex::encode(h.as_bytes()))
                .unwrap_or_else(|| "none".to_string())
        );
        println!(
            "CT-token-type deployed: type_id_hash = 0x{}",
            contracts
                .ct_token_type
                .type_id_hash
                .as_ref()
                .map(|h| hex::encode(h.as_bytes()))
                .unwrap_or_else(|| "none".to_string())
        );
        println!("Checkpoint: block {}", checkpoint);

        // Create faucet
        let faucet = Faucet::new(DevNet::RPC_URL, miner_key, miner_lock_args);

        println!("=== Test environment ready ===\n");

        Ok(Self {
            devnet,
            contracts,
            faucet,
            checkpoint,
            miner_key,
            miner_lock_args,
        })
    }

    /// Deploy contracts and create checkpoint.
    fn deploy_and_checkpoint(
        devnet: &DevNet,
        miner_key: &SecretKey,
        miner_lock_args: &[u8; 20],
    ) -> Result<(DeployedContracts, u64), String> {
        let deployer = ContractDeployer::new(DevNet::RPC_URL, *miner_key, *miner_lock_args);

        // Deploy all contracts
        let contracts = deployer.deploy_all()?;

        // Generate blocks to confirm deployment
        // CKB requires transactions to go through proposal window before being committed.
        // Use enough blocks to ensure the deployment tx is fully confirmed.
        println!("Generating blocks to confirm deployment...");
        devnet.generate_blocks(10)?;

        // Clear tx pool to avoid RBF conflicts with any lingering transactions
        devnet.clear_tx_pool()?;

        // Small delay to allow indexer to sync
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Save checkpoint
        let checkpoint = devnet.get_tip_block_number()?;
        devnet.save_checkpoint(checkpoint)?;

        Ok((contracts, checkpoint))
    }

    /// Reset the chain to checkpoint.
    ///
    /// Call this at the end of each test to ensure isolation.
    pub fn reset(&self) -> Result<(), String> {
        self.devnet.reset_to_checkpoint()
    }

    /// Generate a block.
    pub fn generate_block(&self) -> Result<H256, String> {
        self.devnet.generate_block()
    }

    /// Generate multiple blocks.
    pub fn generate_blocks(&self, count: u64) -> Result<(), String> {
        self.devnet.generate_blocks(count)
    }

    /// Wait for the indexer to sync with the chain tip.
    pub fn wait_for_indexer_sync(&self) -> Result<(), String> {
        self.devnet.wait_for_indexer_sync()
    }

    /// Get the stealth-lock code hash (type_id hash for use with hash_type=Type).
    pub fn stealth_lock_code_hash(&self) -> H256 {
        self.contracts
            .stealth_lock
            .type_id_hash
            .clone()
            .expect("Contract should have type_id_hash")
    }

    /// Get the stealth-lock data hash (for use with hash_type=Data).
    pub fn stealth_lock_data_hash(&self) -> H256 {
        self.contracts.stealth_lock.data_hash.clone()
    }

    /// Get the stealth-lock contract cell dep.
    pub fn stealth_lock_cell_dep(&self) -> (H256, u32) {
        (
            self.contracts.stealth_lock.tx_hash.clone(),
            self.contracts.stealth_lock.output_index,
        )
    }

    /// Get the ckb-auth data hash (for use with hash_type=Data2).
    pub fn ckb_auth_data_hash(&self) -> H256 {
        self.contracts.ckb_auth.data_hash.clone()
    }

    /// Get the ckb-auth cell dep.
    pub fn ckb_auth_cell_dep(&self) -> (H256, u32) {
        (
            self.contracts.ckb_auth.tx_hash.clone(),
            self.contracts.ckb_auth.output_index,
        )
    }

    /// Get the ct-info-type code hash (type_id hash for use with hash_type=Type).
    pub fn ct_info_type_code_hash(&self) -> H256 {
        self.contracts
            .ct_info_type
            .type_id_hash
            .clone()
            .expect("CT-info-type contract should have type_id_hash")
    }

    /// Get the ct-info-type data hash (for use with hash_type=Data).
    pub fn ct_info_type_data_hash(&self) -> H256 {
        self.contracts.ct_info_type.data_hash.clone()
    }

    /// Get the ct-info-type contract cell dep.
    pub fn ct_info_type_cell_dep(&self) -> (H256, u32) {
        (
            self.contracts.ct_info_type.tx_hash.clone(),
            self.contracts.ct_info_type.output_index,
        )
    }

    /// Get the ct-token-type code hash (type_id hash for use with hash_type=Type).
    pub fn ct_token_type_code_hash(&self) -> H256 {
        self.contracts
            .ct_token_type
            .type_id_hash
            .clone()
            .expect("CT-token-type contract should have type_id_hash")
    }

    /// Get the ct-token-type data hash (for use with hash_type=Data).
    pub fn ct_token_type_data_hash(&self) -> H256 {
        self.contracts.ct_token_type.data_hash.clone()
    }

    /// Get the ct-token-type contract cell dep.
    pub fn ct_token_type_cell_dep(&self) -> (H256, u32) {
        (
            self.contracts.ct_token_type.tx_hash.clone(),
            self.contracts.ct_token_type.output_index,
        )
    }
}

/// Macro for creating integration tests with automatic environment setup.
#[macro_export]
macro_rules! integration_test {
    ($name:ident, $body:expr) => {
        #[test]
        fn $name() {
            let env = $crate::TestEnv::get();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body(env)));

            // Always try to reset, even if test panicked
            if let Err(e) = env.reset() {
                eprintln!("Warning: Failed to reset after test: {}", e);
            }

            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
        }
    };
}
