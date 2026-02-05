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
pub mod faucet;

use std::sync::OnceLock;

use ckb_types::H256;
use secp256k1::SecretKey;

use contract_deployer::{ContractDeployer, DeployedContract};
use devnet::DevNet;
use faucet::Faucet;

static TEST_ENV: OnceLock<TestEnv> = OnceLock::new();

/// Test environment for integration tests.
pub struct TestEnv {
    /// DevNet manager.
    pub devnet: DevNet,
    /// Deployed contract info.
    pub contract: DeployedContract,
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
        println!("Miner lock args: 0x{}", hex::encode(&miner_lock_args));

        // Start or detect devnet
        let mut devnet = DevNet::new();
        devnet.start()?;

        // Check if we have a checkpoint (contracts already deployed)
        let (contract, checkpoint) = if let Some(checkpoint) = devnet.load_checkpoint() {
            println!("Found checkpoint at block {}", checkpoint);

            // Load contract info
            if let Some(contract_info) = ContractDeployer::load_deployed_info() {
                // Verify contract is still deployed
                let deployer =
                    ContractDeployer::new(DevNet::RPC_URL, miner_key.clone(), miner_lock_args);
                if deployer.is_deployed(&contract_info)? {
                    println!("Contract still deployed, reusing existing setup");
                    (contract_info, checkpoint)
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
            contract
                .type_id_hash
                .as_ref()
                .map(|h| hex::encode(h.as_bytes()))
                .unwrap_or_else(|| "none".to_string())
        );
        println!("Checkpoint: block {}", checkpoint);

        // Create faucet
        let faucet = Faucet::new(DevNet::RPC_URL, miner_key.clone(), miner_lock_args);

        println!("=== Test environment ready ===\n");

        Ok(Self {
            devnet,
            contract,
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
    ) -> Result<(DeployedContract, u64), String> {
        let deployer = ContractDeployer::new(DevNet::RPC_URL, miner_key.clone(), *miner_lock_args);

        // Deploy stealth-lock contract
        let contract = deployer.deploy_stealth_lock()?;

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

        Ok((contract, checkpoint))
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

    /// Get the stealth-lock code hash (type_id hash for use with hash_type=Type).
    pub fn stealth_lock_code_hash(&self) -> H256 {
        self.contract
            .type_id_hash
            .clone()
            .expect("Contract should have type_id_hash")
    }

    /// Get the stealth-lock data hash (for use with hash_type=Data).
    pub fn stealth_lock_data_hash(&self) -> H256 {
        self.contract.data_hash.clone()
    }

    /// Get the contract cell dep.
    pub fn stealth_lock_cell_dep(&self) -> (H256, u32) {
        (self.contract.tx_hash.clone(), self.contract.output_index)
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
