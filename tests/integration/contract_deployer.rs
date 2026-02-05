//! Contract deployment for integration tests.
//!
//! Deploys the stealth-lock contract to the devnet if not already deployed.

use std::fs;
use std::path::PathBuf;

use ckb_hash::{blake2b_256, new_blake2b};
use ckb_jsonrpc_types::{
    CellDep, CellInput, CellOutput, DepType, JsonBytes, OutPoint, Script, Transaction, Uint32,
    Uint64,
};
use ckb_sdk::CkbRpcClient;
use ckb_sdk::rpc::ckb_indexer::{Order, ScriptType, SearchKey, SearchMode};
use ckb_types::H256;
use ckb_types::packed;
use ckb_types::prelude::*;
use secp256k1::{Message, Secp256k1, SecretKey};

/// Type ID code hash (special hash for TYPE_ID system script).
/// This is "TYPE_ID" in ASCII, right-padded with zeros to 32 bytes.
pub const TYPE_ID_CODE_HASH: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x49, 0x44,
];

/// SECP256K1_BLAKE160_SIGHASH_ALL code hash (system cell).
pub const SIGHASH_ALL_CODE_HASH: &str =
    "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";

/// Deployed contract information.
#[derive(Debug, Clone)]
pub struct DeployedContract {
    /// Transaction hash where the contract was deployed.
    pub tx_hash: H256,
    /// Output index in the deployment transaction.
    pub output_index: u32,
    /// Code hash (data hash of the contract binary).
    pub data_hash: H256,
    /// Type ID hash (if using type_id).
    pub type_id_hash: Option<H256>,
}

/// All deployed contracts for integration tests.
#[derive(Debug, Clone)]
pub struct DeployedContracts {
    /// Stealth-lock contract info.
    pub stealth_lock: DeployedContract,
    /// CKB-auth contract info.
    pub ckb_auth: DeployedContract,
    /// CT-info-type contract info.
    pub ct_info_type: DeployedContract,
    /// CT-token-type contract info.
    pub ct_token_type: DeployedContract,
}

/// Contract deployer for integration tests.
pub struct ContractDeployer {
    client: CkbRpcClient,
    miner_key: SecretKey,
    miner_lock_args: [u8; 20],
}

impl ContractDeployer {
    /// Create a new contract deployer.
    pub fn new(rpc_url: &str, miner_key: SecretKey, miner_lock_args: [u8; 20]) -> Self {
        let client = CkbRpcClient::new(rpc_url);
        Self {
            client,
            miner_key,
            miner_lock_args,
        }
    }

    /// Get the path to the deployed contracts info file.
    fn contracts_info_file() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("devnet")
            .join(".contracts")
    }

    /// Load deployed contracts info from file.
    pub fn load_deployed_info() -> Option<DeployedContracts> {
        let path = Self::contracts_info_file();
        if !path.exists() {
            return None;
        }

        let content = fs::read_to_string(&path).ok()?;
        let mut lines = content.lines();

        // Parse stealth-lock info
        let stealth_tx_hash = lines.next()?;
        let stealth_output_index: u32 = lines.next()?.parse().ok()?;
        let stealth_data_hash = lines.next()?;
        let stealth_type_id_hash = lines.next();

        // Parse ckb-auth info
        let auth_tx_hash = lines.next()?;
        let auth_output_index: u32 = lines.next()?.parse().ok()?;
        let auth_data_hash = lines.next()?;

        // Parse ct-info-type info
        let ct_info_tx_hash = lines.next()?;
        let ct_info_output_index: u32 = lines.next()?.parse().ok()?;
        let ct_info_data_hash = lines.next()?;
        let ct_info_type_id_hash = lines.next();

        // Parse ct-token-type info
        let ct_token_tx_hash = lines.next()?;
        let ct_token_output_index: u32 = lines.next()?.parse().ok()?;
        let ct_token_data_hash = lines.next()?;
        let ct_token_type_id_hash = lines.next();

        Some(DeployedContracts {
            stealth_lock: DeployedContract {
                tx_hash: H256::from_slice(
                    &hex::decode(stealth_tx_hash.trim_start_matches("0x")).ok()?,
                )
                .ok()?,
                output_index: stealth_output_index,
                data_hash: H256::from_slice(
                    &hex::decode(stealth_data_hash.trim_start_matches("0x")).ok()?,
                )
                .ok()?,
                type_id_hash: stealth_type_id_hash.and_then(|h| {
                    if h.is_empty() {
                        None
                    } else {
                        H256::from_slice(&hex::decode(h.trim_start_matches("0x")).ok()?).ok()
                    }
                }),
            },
            ckb_auth: DeployedContract {
                tx_hash: H256::from_slice(
                    &hex::decode(auth_tx_hash.trim_start_matches("0x")).ok()?,
                )
                .ok()?,
                output_index: auth_output_index,
                data_hash: H256::from_slice(
                    &hex::decode(auth_data_hash.trim_start_matches("0x")).ok()?,
                )
                .ok()?,
                type_id_hash: None, // ckb-auth doesn't use type_id
            },
            ct_info_type: DeployedContract {
                tx_hash: H256::from_slice(
                    &hex::decode(ct_info_tx_hash.trim_start_matches("0x")).ok()?,
                )
                .ok()?,
                output_index: ct_info_output_index,
                data_hash: H256::from_slice(
                    &hex::decode(ct_info_data_hash.trim_start_matches("0x")).ok()?,
                )
                .ok()?,
                type_id_hash: ct_info_type_id_hash.and_then(|h| {
                    if h.is_empty() {
                        None
                    } else {
                        H256::from_slice(&hex::decode(h.trim_start_matches("0x")).ok()?).ok()
                    }
                }),
            },
            ct_token_type: DeployedContract {
                tx_hash: H256::from_slice(
                    &hex::decode(ct_token_tx_hash.trim_start_matches("0x")).ok()?,
                )
                .ok()?,
                output_index: ct_token_output_index,
                data_hash: H256::from_slice(
                    &hex::decode(ct_token_data_hash.trim_start_matches("0x")).ok()?,
                )
                .ok()?,
                type_id_hash: ct_token_type_id_hash.and_then(|h| {
                    if h.is_empty() {
                        None
                    } else {
                        H256::from_slice(&hex::decode(h.trim_start_matches("0x")).ok()?).ok()
                    }
                }),
            },
        })
    }

    /// Save deployed contracts info to file.
    fn save_deployed_info(info: &DeployedContracts) -> Result<(), String> {
        let path = Self::contracts_info_file();
        let content = format!(
            "0x{}\n{}\n0x{}\n{}\n0x{}\n{}\n0x{}\n0x{}\n{}\n0x{}\n{}\n0x{}\n{}\n0x{}\n{}",
            hex::encode(info.stealth_lock.tx_hash.as_bytes()),
            info.stealth_lock.output_index,
            hex::encode(info.stealth_lock.data_hash.as_bytes()),
            info.stealth_lock
                .type_id_hash
                .as_ref()
                .map(|h| format!("0x{}", hex::encode(h.as_bytes())))
                .unwrap_or_default(),
            hex::encode(info.ckb_auth.tx_hash.as_bytes()),
            info.ckb_auth.output_index,
            hex::encode(info.ckb_auth.data_hash.as_bytes()),
            hex::encode(info.ct_info_type.tx_hash.as_bytes()),
            info.ct_info_type.output_index,
            hex::encode(info.ct_info_type.data_hash.as_bytes()),
            info.ct_info_type
                .type_id_hash
                .as_ref()
                .map(|h| format!("0x{}", hex::encode(h.as_bytes())))
                .unwrap_or_default(),
            hex::encode(info.ct_token_type.tx_hash.as_bytes()),
            info.ct_token_type.output_index,
            hex::encode(info.ct_token_type.data_hash.as_bytes()),
            info.ct_token_type
                .type_id_hash
                .as_ref()
                .map(|h| format!("0x{}", hex::encode(h.as_bytes())))
                .unwrap_or_default(),
        );
        fs::write(&path, content).map_err(|e| format!("Failed to save contracts info: {}", e))
    }

    /// Check if a contract is already deployed by checking if the cell exists.
    pub fn is_deployed(&self, info: &DeployedContract) -> Result<bool, String> {
        // Try to get the cell
        let out_point = ckb_jsonrpc_types::OutPoint {
            tx_hash: info.tx_hash.clone(),
            index: Uint32::from(info.output_index),
        };

        match self.client.get_live_cell(out_point, false) {
            Ok(response) => {
                // Cell exists if status is "live"
                Ok(response.status == "live")
            }
            Err(_) => Ok(false),
        }
    }

    /// Check if all contracts are deployed.
    pub fn are_all_deployed(&self, info: &DeployedContracts) -> Result<bool, String> {
        Ok(self.is_deployed(&info.stealth_lock)?
            && self.is_deployed(&info.ckb_auth)?
            && self.is_deployed(&info.ct_info_type)?
            && self.is_deployed(&info.ct_token_type)?)
    }

    /// Deploy all contracts (stealth-lock, ckb-auth, ct-info-type, ct-token-type).
    ///
    /// Returns the deployed contracts info.
    /// Note: This function generates blocks to confirm each deployment.
    pub fn deploy_all(&self) -> Result<DeployedContracts, String> {
        // Check if already deployed
        if let Some(info) = Self::load_deployed_info()
            && self.are_all_deployed(&info)?
        {
            println!(
                "Contracts already deployed - stealth-lock tx: 0x{}, ckb-auth tx: 0x{}, ct-info-type tx: 0x{}, ct-token-type tx: 0x{}",
                hex::encode(info.stealth_lock.tx_hash.as_bytes()),
                hex::encode(info.ckb_auth.tx_hash.as_bytes()),
                hex::encode(info.ct_info_type.tx_hash.as_bytes()),
                hex::encode(info.ct_token_type.tx_hash.as_bytes())
            );
            return Ok(info);
        }

        println!("Deploying contracts...");

        // Deploy ckb-auth first (stealth-lock depends on it)
        let ckb_auth = self.deploy_ckb_auth()?;
        println!(
            "CKB-auth deployed: tx_hash=0x{}, data_hash=0x{}",
            hex::encode(ckb_auth.tx_hash.as_bytes()),
            hex::encode(ckb_auth.data_hash.as_bytes())
        );

        // Generate blocks to confirm ckb-auth deployment and wait for indexer
        println!("Generating blocks to confirm ckb-auth...");
        self.generate_blocks(4)?;
        self.wait_for_indexer_sync()?;

        // Deploy stealth-lock
        let stealth_lock = self.deploy_stealth_lock_contract()?;
        println!(
            "Stealth-lock deployed: tx_hash=0x{}, type_id_hash=0x{}",
            hex::encode(stealth_lock.tx_hash.as_bytes()),
            stealth_lock
                .type_id_hash
                .as_ref()
                .map(|h| hex::encode(h.as_bytes()))
                .unwrap_or_else(|| "none".to_string())
        );

        // Generate blocks to confirm stealth-lock deployment and wait for indexer
        println!("Generating blocks to confirm stealth-lock...");
        self.generate_blocks(4)?;
        self.wait_for_indexer_sync()?;

        // Deploy ct-info-type
        let ct_info_type = self.deploy_ct_info_type_contract()?;
        println!(
            "CT-info-type deployed: tx_hash=0x{}, type_id_hash=0x{}",
            hex::encode(ct_info_type.tx_hash.as_bytes()),
            ct_info_type
                .type_id_hash
                .as_ref()
                .map(|h| hex::encode(h.as_bytes()))
                .unwrap_or_else(|| "none".to_string())
        );

        // Generate blocks to confirm ct-info-type deployment and wait for indexer
        println!("Generating blocks to confirm ct-info-type...");
        self.generate_blocks(4)?;
        self.wait_for_indexer_sync()?;

        // Deploy ct-token-type
        let ct_token_type = self.deploy_ct_token_type_contract()?;
        println!(
            "CT-token-type deployed: tx_hash=0x{}, type_id_hash=0x{}",
            hex::encode(ct_token_type.tx_hash.as_bytes()),
            ct_token_type
                .type_id_hash
                .as_ref()
                .map(|h| hex::encode(h.as_bytes()))
                .unwrap_or_else(|| "none".to_string())
        );

        let info = DeployedContracts {
            stealth_lock,
            ckb_auth,
            ct_info_type,
            ct_token_type,
        };

        // Save deployment info
        Self::save_deployed_info(&info)?;

        Ok(info)
    }

    /// Generate blocks using the CKB miner RPC.
    fn generate_blocks(&self, count: u64) -> Result<(), String> {
        for _ in 0..count {
            self.client
                .generate_block()
                .map_err(|e| format!("Failed to generate block: {}", e))?;
        }
        Ok(())
    }

    /// Wait for the indexer to sync with the chain tip.
    fn wait_for_indexer_sync(&self) -> Result<(), String> {
        let max_wait = std::time::Duration::from_secs(10);
        let start = std::time::Instant::now();
        let poll_interval = std::time::Duration::from_millis(200);

        loop {
            let chain_tip = self
                .client
                .get_tip_block_number()
                .map(|n| n.value())
                .map_err(|e| format!("Failed to get tip block number: {}", e))?;

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

    /// Deploy the ckb-auth contract.
    fn deploy_ckb_auth(&self) -> Result<DeployedContract, String> {
        println!("Deploying ckb-auth contract...");

        // Load contract binary
        let contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("ckb-auth");

        let contract_code = fs::read(&contract_path)
            .map_err(|e| format!("Failed to read ckb-auth binary: {}", e))?;

        let data_hash = H256::from_slice(&blake2b_256(&contract_code)).unwrap();
        println!(
            "CKB-auth data hash: 0x{}",
            hex::encode(data_hash.as_bytes())
        );

        // Deploy as a simple data cell (no type_id needed, referenced by data hash)
        self.deploy_data_cell(&contract_code, data_hash)
    }

    /// Deploy the stealth-lock contract.
    fn deploy_stealth_lock_contract(&self) -> Result<DeployedContract, String> {
        println!("Deploying stealth-lock contract...");

        // Load contract binary
        let contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("stealth-lock");

        let contract_code = fs::read(&contract_path)
            .map_err(|e| format!("Failed to read contract binary: {}", e))?;

        let data_hash = H256::from_slice(&blake2b_256(&contract_code)).unwrap();
        println!(
            "Contract data hash: 0x{}",
            hex::encode(data_hash.as_bytes())
        );

        // Get miner cells for input
        let miner_cells = self.get_miner_cells()?;
        if miner_cells.is_empty() {
            return Err("No miner cells available for deployment".to_string());
        }

        // Calculate required capacity
        // Cell: 8 (capacity) + 53 (lock script: 32 code_hash + 1 hash_type + 20 args)
        //     + 65 (type script: 32 code_hash + 1 hash_type + 32 args) + data_size
        let lock_script_size = 32 + 1 + 20; // code_hash + hash_type + args(20 bytes)
        let type_script_size = 32 + 1 + 32; // code_hash + hash_type + args(32 bytes)
        let data_size = contract_code.len() as u64;
        let required_capacity = (8 + lock_script_size + type_script_size + data_size) * 100_000_000;

        // Select inputs
        let mut selected_inputs = Vec::new();
        let mut total_input: u64 = 0;
        let fee = 100_000u64; // 0.001 CKB fee

        for cell in &miner_cells {
            if total_input >= required_capacity + fee {
                break;
            }
            total_input += cell.1;
            selected_inputs.push(cell.clone());
        }

        if total_input < required_capacity + fee {
            return Err(format!(
                "Insufficient capacity: need {} CKB, have {} CKB",
                (required_capacity + fee) / 100_000_000,
                total_input / 100_000_000
            ));
        }

        // Build inputs
        let inputs: Vec<CellInput> = selected_inputs
            .iter()
            .map(|(out_point, _)| CellInput {
                previous_output: out_point.clone(),
                since: Uint64::from(0u64),
            })
            .collect();

        // Calculate type_id args: hash(first_input || output_index)
        let type_id_args = self.calculate_type_id_args(&inputs[0], 0);
        let _type_id_hash = H256::from_slice(&blake2b_256({
            // Hash the type script to get the type_id_hash
            let type_script = Script {
                code_hash: H256::from_slice(&TYPE_ID_CODE_HASH).unwrap(),
                hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
                args: JsonBytes::from_vec(type_id_args.to_vec()),
            };
            self.script_hash(&type_script)
        }))
        .unwrap();

        // Build outputs
        let miner_lock = self.build_miner_lock();

        let code_cell = CellOutput {
            capacity: Uint64::from(required_capacity),
            lock: miner_lock.clone(), // Lock with miner's key
            type_: Some(Script {
                code_hash: H256::from_slice(&TYPE_ID_CODE_HASH).unwrap(),
                hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
                args: JsonBytes::from_vec(type_id_args.to_vec()),
            }),
        };

        let change_amount = total_input - required_capacity - fee;
        let change_cell = CellOutput {
            capacity: Uint64::from(change_amount),
            lock: miner_lock,
            type_: None,
        };

        let outputs = vec![code_cell, change_cell];
        let outputs_data = vec![
            JsonBytes::from_vec(contract_code),
            JsonBytes::default(), // Empty data for change cell
        ];

        // Build cell deps (secp256k1_blake160_sighash_all dep group)
        // The dep group is in the second genesis transaction (index 1), output 0
        let dep_group_out_point = self.get_sighash_dep_group()?;
        let cell_deps = vec![CellDep {
            out_point: dep_group_out_point,
            dep_type: DepType::DepGroup,
        }];

        // Build transaction
        let tx = Transaction {
            version: Uint32::from(0u32),
            cell_deps,
            header_deps: vec![],
            inputs,
            outputs,
            outputs_data,
            witnesses: vec![JsonBytes::default(); selected_inputs.len()],
        };

        // Calculate tx hash and sign
        let tx_hash = self.calculate_tx_hash(&tx);
        let signed_tx = self.sign_transaction(tx, &tx_hash)?;

        // Send transaction
        let sent_hash = self
            .client
            .send_transaction(signed_tx, None)
            .map_err(|e| format!("Failed to send deployment tx: {}", e))?;

        println!(
            "Deployment transaction sent: 0x{}",
            hex::encode(sent_hash.as_bytes())
        );

        let info = DeployedContract {
            tx_hash: sent_hash,
            output_index: 0,
            data_hash,
            type_id_hash: Some(
                H256::from_slice(&self.script_hash(&Script {
                    code_hash: H256::from_slice(&TYPE_ID_CODE_HASH).unwrap(),
                    hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
                    args: JsonBytes::from_vec(type_id_args.to_vec()),
                }))
                .unwrap(),
            ),
        };

        Ok(info)
    }

    /// Deploy the ct-info-type contract.
    fn deploy_ct_info_type_contract(&self) -> Result<DeployedContract, String> {
        println!("Deploying ct-info-type contract...");

        let contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("ct-info-type");

        let contract_code = fs::read(&contract_path)
            .map_err(|e| format!("Failed to read ct-info-type binary: {}", e))?;

        let data_hash = H256::from_slice(&blake2b_256(&contract_code)).unwrap();
        println!(
            "CT-info-type data hash: 0x{}",
            hex::encode(data_hash.as_bytes())
        );

        self.deploy_contract_with_type_id(&contract_code, data_hash)
    }

    /// Deploy the ct-token-type contract.
    fn deploy_ct_token_type_contract(&self) -> Result<DeployedContract, String> {
        println!("Deploying ct-token-type contract...");

        let contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("ct-token-type");

        let contract_code = fs::read(&contract_path)
            .map_err(|e| format!("Failed to read ct-token-type binary: {}", e))?;

        let data_hash = H256::from_slice(&blake2b_256(&contract_code)).unwrap();
        println!(
            "CT-token-type data hash: 0x{}",
            hex::encode(data_hash.as_bytes())
        );

        self.deploy_contract_with_type_id(&contract_code, data_hash)
    }

    /// Deploy a contract with TYPE_ID.
    fn deploy_contract_with_type_id(
        &self,
        contract_code: &[u8],
        data_hash: H256,
    ) -> Result<DeployedContract, String> {
        // Get miner cells for input
        let miner_cells = self.get_miner_cells()?;
        if miner_cells.is_empty() {
            return Err("No miner cells available for deployment".to_string());
        }

        // Calculate required capacity
        let lock_script_size = 32 + 1 + 20; // code_hash + hash_type + args(20 bytes)
        let type_script_size = 32 + 1 + 32; // code_hash + hash_type + args(32 bytes)
        let data_size = contract_code.len() as u64;
        let required_capacity = (8 + lock_script_size + type_script_size + data_size) * 100_000_000;

        // Calculate fee based on transaction size
        // Min fee rate is 1000 shannons/KB, we'll use a safe margin
        // Estimate tx size: inputs (44 bytes each) + outputs (~65 bytes each) + data_size + witness (~90 bytes)
        let estimated_tx_size = 200 + data_size;
        let fee = std::cmp::max(200_000u64, (estimated_tx_size * 1000 / 1000) + 50_000); // 1000 shannons/KB + margin

        // Select inputs
        let mut selected_inputs = Vec::new();
        let mut total_input: u64 = 0;

        for cell in &miner_cells {
            if total_input >= required_capacity + fee {
                break;
            }
            total_input += cell.1;
            selected_inputs.push(cell.clone());
        }

        if total_input < required_capacity + fee {
            return Err(format!(
                "Insufficient capacity: need {} CKB, have {} CKB",
                (required_capacity + fee) / 100_000_000,
                total_input / 100_000_000
            ));
        }

        // Build inputs
        let inputs: Vec<CellInput> = selected_inputs
            .iter()
            .map(|(out_point, _)| CellInput {
                previous_output: out_point.clone(),
                since: Uint64::from(0u64),
            })
            .collect();

        // Calculate type_id args
        let type_id_args = self.calculate_type_id_args(&inputs[0], 0);

        // Build outputs
        let miner_lock = self.build_miner_lock();

        let code_cell = CellOutput {
            capacity: Uint64::from(required_capacity),
            lock: miner_lock.clone(),
            type_: Some(Script {
                code_hash: H256::from_slice(&TYPE_ID_CODE_HASH).unwrap(),
                hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
                args: JsonBytes::from_vec(type_id_args.to_vec()),
            }),
        };

        let change_amount = total_input - required_capacity - fee;
        let change_cell = CellOutput {
            capacity: Uint64::from(change_amount),
            lock: miner_lock,
            type_: None,
        };

        let outputs = vec![code_cell, change_cell];
        let outputs_data = vec![
            JsonBytes::from_vec(contract_code.to_vec()),
            JsonBytes::default(),
        ];

        // Build cell deps
        let dep_group_out_point = self.get_sighash_dep_group()?;
        let cell_deps = vec![CellDep {
            out_point: dep_group_out_point,
            dep_type: DepType::DepGroup,
        }];

        // Build transaction
        let tx = Transaction {
            version: Uint32::from(0u32),
            cell_deps,
            header_deps: vec![],
            inputs,
            outputs,
            outputs_data,
            witnesses: vec![JsonBytes::default(); selected_inputs.len()],
        };

        // Calculate tx hash and sign
        let tx_hash = self.calculate_tx_hash(&tx);
        let signed_tx = self.sign_transaction(tx, &tx_hash)?;

        // Send transaction
        let sent_hash = self
            .client
            .send_transaction(signed_tx, None)
            .map_err(|e| format!("Failed to send deployment tx: {}", e))?;

        println!(
            "Deployment transaction sent: 0x{}",
            hex::encode(sent_hash.as_bytes())
        );

        Ok(DeployedContract {
            tx_hash: sent_hash,
            output_index: 0,
            data_hash,
            type_id_hash: Some(
                H256::from_slice(&self.script_hash(&Script {
                    code_hash: H256::from_slice(&TYPE_ID_CODE_HASH).unwrap(),
                    hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
                    args: JsonBytes::from_vec(type_id_args.to_vec()),
                }))
                .unwrap(),
            ),
        })
    }

    /// Deploy a data cell (simple cell with contract code, no type_id).
    fn deploy_data_cell(
        &self,
        contract_code: &[u8],
        data_hash: H256,
    ) -> Result<DeployedContract, String> {
        // Get miner cells for input
        let miner_cells = self.get_miner_cells()?;
        if miner_cells.is_empty() {
            return Err("No miner cells available for deployment".to_string());
        }

        // Calculate required capacity
        // Cell: 8 (capacity) + 53 (lock script) + data_size
        let lock_script_size = 32 + 1 + 20; // code_hash + hash_type + args(20 bytes)
        let data_size = contract_code.len() as u64;
        let required_capacity = (8 + lock_script_size + data_size) * 100_000_000;

        // Calculate fee based on transaction size
        // Min fee rate is 1000 shannons/KB, we'll use a safe margin
        // Estimate tx size: inputs (44 bytes each) + outputs (~65 bytes each) + data_size + witness (~90 bytes)
        let estimated_tx_size = 200 + data_size; // conservative estimate
        let fee = std::cmp::max(200_000u64, (estimated_tx_size * 1000 / 1000) + 50_000); // 1000 shannons/KB + margin

        // Select inputs
        let mut selected_inputs = Vec::new();
        let mut total_input: u64 = 0;

        for cell in &miner_cells {
            if total_input >= required_capacity + fee {
                break;
            }
            total_input += cell.1;
            selected_inputs.push(cell.clone());
        }

        if total_input < required_capacity + fee {
            return Err(format!(
                "Insufficient capacity: need {} CKB, have {} CKB",
                (required_capacity + fee) / 100_000_000,
                total_input / 100_000_000
            ));
        }

        // Build inputs
        let inputs: Vec<CellInput> = selected_inputs
            .iter()
            .map(|(out_point, _)| CellInput {
                previous_output: out_point.clone(),
                since: Uint64::from(0u64),
            })
            .collect();

        // Build outputs
        let miner_lock = self.build_miner_lock();

        let code_cell = CellOutput {
            capacity: Uint64::from(required_capacity),
            lock: miner_lock.clone(),
            type_: None, // No type script for simple data cell
        };

        let change_amount = total_input - required_capacity - fee;
        let change_cell = CellOutput {
            capacity: Uint64::from(change_amount),
            lock: miner_lock,
            type_: None,
        };

        let outputs = vec![code_cell, change_cell];
        let outputs_data = vec![
            JsonBytes::from_vec(contract_code.to_vec()),
            JsonBytes::default(),
        ];

        // Build cell deps
        let dep_group_out_point = self.get_sighash_dep_group()?;
        let cell_deps = vec![CellDep {
            out_point: dep_group_out_point,
            dep_type: DepType::DepGroup,
        }];

        // Build transaction
        let tx = Transaction {
            version: Uint32::from(0u32),
            cell_deps,
            header_deps: vec![],
            inputs,
            outputs,
            outputs_data,
            witnesses: vec![JsonBytes::default(); selected_inputs.len()],
        };

        // Calculate tx hash and sign
        let tx_hash = self.calculate_tx_hash(&tx);
        let signed_tx = self.sign_transaction(tx, &tx_hash)?;

        // Send transaction
        let sent_hash = self
            .client
            .send_transaction(signed_tx, None)
            .map_err(|e| format!("Failed to send deployment tx: {}", e))?;

        println!(
            "Data cell deployment transaction sent: 0x{}",
            hex::encode(sent_hash.as_bytes())
        );

        Ok(DeployedContract {
            tx_hash: sent_hash,
            output_index: 0,
            data_hash,
            type_id_hash: None,
        })
    }

    /// Get the sighash_all dep group out point from genesis.
    fn get_sighash_dep_group(&self) -> Result<OutPoint, String> {
        use ckb_jsonrpc_types::BlockNumber;

        // Get the genesis block
        let genesis = self
            .client
            .get_block_by_number(BlockNumber::from(0u64))
            .map_err(|e| format!("Failed to get genesis block: {}", e))?
            .ok_or_else(|| "Genesis block not found".to_string())?;

        // The dep group is in the second transaction (index 1), output 0
        if genesis.transactions.len() < 2 {
            return Err("Genesis block doesn't have dep group transaction".to_string());
        }

        let dep_group_tx = &genesis.transactions[1];
        Ok(OutPoint {
            tx_hash: dep_group_tx.hash.clone(),
            index: Uint32::from(0u32), // secp256k1_blake160_sighash_all dep group at index 0
        })
    }

    /// Get cells owned by the miner.
    fn get_miner_cells(&self) -> Result<Vec<(OutPoint, u64)>, String> {
        let miner_lock = self.build_miner_lock();

        let search_key = SearchKey {
            script: miner_lock,
            script_type: ScriptType::Lock,
            script_search_mode: Some(SearchMode::Exact),
            filter: None,
            with_data: Some(false),
            group_by_transaction: None,
        };

        let result = self
            .client
            .get_cells(search_key, Order::Asc, 100.into(), None)
            .map_err(|e| format!("Failed to get miner cells: {}", e))?;

        let cells: Vec<(OutPoint, u64)> = result
            .objects
            .into_iter()
            .map(|cell| {
                let out_point = OutPoint {
                    tx_hash: cell.out_point.tx_hash,
                    index: cell.out_point.index,
                };
                let capacity: u64 = cell.output.capacity.into();
                (out_point, capacity)
            })
            .collect();

        Ok(cells)
    }

    /// Build miner's lock script.
    fn build_miner_lock(&self) -> Script {
        Script {
            code_hash: H256::from_slice(&hex::decode(SIGHASH_ALL_CODE_HASH).unwrap()).unwrap(),
            hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
            args: JsonBytes::from_vec(self.miner_lock_args.to_vec()),
        }
    }

    /// Calculate type_id args.
    /// The args = blake2b(first_cell_input || output_index)
    /// where first_cell_input is the molecule-serialized CellInput
    fn calculate_type_id_args(&self, first_input: &CellInput, output_index: u64) -> [u8; 32] {
        // Serialize the CellInput in molecule format
        let cell_input = packed::CellInput::new_builder()
            .previous_output(
                packed::OutPoint::new_builder()
                    .tx_hash(
                        packed::Byte32::from_slice(first_input.previous_output.tx_hash.as_bytes())
                            .unwrap(),
                    )
                    .index(
                        packed::Uint32::from_slice(
                            &first_input.previous_output.index.value().to_le_bytes(),
                        )
                        .unwrap(),
                    )
                    .build(),
            )
            .since(packed::Uint64::from_slice(&first_input.since.value().to_le_bytes()).unwrap())
            .build();

        let mut data = Vec::new();
        data.extend_from_slice(cell_input.as_slice());
        data.extend_from_slice(&output_index.to_le_bytes());
        blake2b_256(&data)
    }

    /// Calculate script hash.
    fn script_hash(&self, script: &Script) -> [u8; 32] {
        let packed_script = packed::Script::new_builder()
            .code_hash(packed::Byte32::from_slice(script.code_hash.as_bytes()).unwrap())
            .hash_type(match script.hash_type {
                ckb_jsonrpc_types::ScriptHashType::Data => packed::Byte::new(0),
                ckb_jsonrpc_types::ScriptHashType::Type => packed::Byte::new(1),
                ckb_jsonrpc_types::ScriptHashType::Data1 => packed::Byte::new(2),
                ckb_jsonrpc_types::ScriptHashType::Data2 => packed::Byte::new(4),
                _ => packed::Byte::new(1),
            })
            .args(script.args.as_bytes().to_vec().pack())
            .build();
        blake2b_256(packed_script.as_slice())
    }

    /// Calculate transaction hash using ckb-types' proper serialization.
    fn calculate_tx_hash(&self, tx: &Transaction) -> H256 {
        // Convert to packed::Transaction and use its calc_tx_hash method
        let packed_tx: packed::Transaction = tx.clone().into();
        H256::from_slice(packed_tx.calc_tx_hash().as_slice()).unwrap()
    }

    /// Sign the transaction with the miner key.
    fn sign_transaction(&self, tx: Transaction, tx_hash: &H256) -> Result<Transaction, String> {
        let secp = Secp256k1::new();

        // Build witness args with placeholder for signature (65 bytes for recoverable signature)
        let zero_lock: ckb_types::bytes::Bytes = vec![0u8; 65].into();
        let placeholder_witness = packed::WitnessArgs::new_builder()
            .lock(Some(zero_lock).pack())
            .build();

        // Calculate message to sign using incremental blake2b (matching CKB reference)
        let mut blake2b = new_blake2b();
        blake2b.update(tx_hash.as_bytes());

        let witness_bytes = placeholder_witness.as_bytes();
        blake2b.update(&(witness_bytes.len() as u64).to_le_bytes());
        blake2b.update(&witness_bytes);

        // For additional witnesses in same script group (beyond the first input)
        // Note: For single-input transactions this loop doesn't execute
        for i in 1..tx.inputs.len() {
            // Get existing witness or use empty
            let witness_data = if i < tx.witnesses.len() {
                tx.witnesses[i].as_bytes().to_vec()
            } else {
                vec![]
            };
            blake2b.update(&(witness_data.len() as u64).to_le_bytes());
            blake2b.update(&witness_data);
        }

        let mut message_hash = [0u8; 32];
        blake2b.finalize(&mut message_hash);

        let message = Message::from_digest(message_hash);

        // Sign with recoverable signature
        let sig = secp.sign_ecdsa_recoverable(&message, &self.miner_key);
        let (recovery_id, signature_bytes) = sig.serialize_compact();

        // Build signature: [r(32) || s(32) || v(1)]
        let mut signature = signature_bytes.to_vec();
        signature.push(recovery_id.to_i32() as u8);

        let signed_witness = packed::WitnessArgs::new_builder()
            .lock(Some(ckb_types::bytes::Bytes::from(signature)).pack())
            .build();

        let mut witnesses: Vec<JsonBytes> =
            vec![JsonBytes::from_vec(signed_witness.as_bytes().to_vec())];

        // Add empty witnesses for other inputs
        for _ in 1..tx.inputs.len() {
            witnesses.push(JsonBytes::default());
        }

        Ok(Transaction {
            version: tx.version,
            cell_deps: tx.cell_deps,
            header_deps: tx.header_deps,
            inputs: tx.inputs,
            outputs: tx.outputs,
            outputs_data: tx.outputs_data,
            witnesses,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_miner_key_derivation() {
        // This test verifies that our key derivation matches what we expect
        let privkey_hex = "d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc";
        let privkey_bytes = hex::decode(privkey_hex).unwrap();
        let secret_key = SecretKey::from_slice(&privkey_bytes).unwrap();

        let secp = Secp256k1::new();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        // CKB uses compressed public key (33 bytes)
        let compressed_pubkey = public_key.serialize();
        assert_eq!(compressed_pubkey.len(), 33, "Should be compressed pubkey");

        // Blake2b-256 hash then take first 20 bytes
        let hash = blake2b_256(compressed_pubkey);
        let lock_args: [u8; 20] = hash[0..20].try_into().unwrap();

        let expected = "c8328aabcd9b9e8e64fbc566c4385c3bdeb219d7";
        let actual = hex::encode(lock_args);
        assert_eq!(
            actual, expected,
            "Miner key derivation should match expected lock args"
        );

        println!("Public key: 0x{}", hex::encode(compressed_pubkey));
        println!("Lock args:  0x{}", actual);
    }

    #[test]
    fn test_type_id_code_hash() {
        // TYPE_ID code hash should be "TYPE_ID" in ASCII at the end (bytes 25-31)
        // The hex is: 00...00 54 59 50 45 5f 49 44
        //              zeros  T  Y  P  E  _  I  D
        let expected_suffix = b"TYPE_ID";
        let actual_suffix = &TYPE_ID_CODE_HASH[25..32];
        assert_eq!(
            actual_suffix, expected_suffix,
            "TYPE_ID code hash should end with ASCII 'TYPE_ID'"
        );

        // First 25 bytes should be zeros
        assert!(
            TYPE_ID_CODE_HASH[0..25].iter().all(|&b| b == 0),
            "TYPE_ID code hash should have leading zeros"
        );
    }
}
