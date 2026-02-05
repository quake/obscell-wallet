//! Contract deployment for integration tests.
//!
//! Deploys the stealth-lock contract to the devnet if not already deployed.

use std::fs;
use std::path::PathBuf;

use ckb_hash::blake2b_256;
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

    /// Load deployed contract info from file.
    pub fn load_deployed_info() -> Option<DeployedContract> {
        let path = Self::contracts_info_file();
        if !path.exists() {
            return None;
        }

        let content = fs::read_to_string(&path).ok()?;
        let mut lines = content.lines();

        let tx_hash = lines.next()?;
        let output_index: u32 = lines.next()?.parse().ok()?;
        let data_hash = lines.next()?;
        let type_id_hash = lines.next();

        Some(DeployedContract {
            tx_hash: H256::from_slice(&hex::decode(tx_hash.trim_start_matches("0x")).ok()?).ok()?,
            output_index,
            data_hash: H256::from_slice(&hex::decode(data_hash.trim_start_matches("0x")).ok()?)
                .ok()?,
            type_id_hash: type_id_hash.and_then(|h| {
                H256::from_slice(&hex::decode(h.trim_start_matches("0x")).ok()?).ok()
            }),
        })
    }

    /// Save deployed contract info to file.
    fn save_deployed_info(info: &DeployedContract) -> Result<(), String> {
        let path = Self::contracts_info_file();
        let content = format!(
            "0x{}\n{}\n0x{}\n{}",
            hex::encode(info.tx_hash.as_bytes()),
            info.output_index,
            hex::encode(info.data_hash.as_bytes()),
            info.type_id_hash
                .as_ref()
                .map(|h| format!("0x{}", hex::encode(h.as_bytes())))
                .unwrap_or_default()
        );
        fs::write(&path, content).map_err(|e| format!("Failed to save contracts info: {}", e))
    }

    /// Check if the contract is already deployed by checking if the cell exists.
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

    /// Deploy the stealth-lock contract.
    ///
    /// Returns the deployed contract info.
    pub fn deploy_stealth_lock(&self) -> Result<DeployedContract, String> {
        // Check if already deployed
        if let Some(info) = Self::load_deployed_info()
            && self.is_deployed(&info)?
        {
            println!(
                "Stealth-lock contract already deployed at tx: 0x{}",
                hex::encode(info.tx_hash.as_bytes())
            );
            return Ok(info);
        }

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
        let _type_id_hash = H256::from_slice(&blake2b_256(&{
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

        // Save deployment info
        Self::save_deployed_info(&info)?;

        Ok(info)
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
            .since(
                packed::Uint64::from_slice(&first_input.since.value().to_le_bytes()).unwrap(),
            )
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

    /// Calculate transaction hash.
    fn calculate_tx_hash(&self, tx: &Transaction) -> H256 {
        let raw_tx = packed::RawTransaction::new_builder()
            .version(packed::Uint32::from_slice(&tx.version.value().to_le_bytes()).unwrap())
            .cell_deps(
                tx.cell_deps
                    .iter()
                    .map(|dep| {
                        packed::CellDep::new_builder()
                            .out_point(
                                packed::OutPoint::new_builder()
                                    .tx_hash(
                                        packed::Byte32::from_slice(
                                            dep.out_point.tx_hash.as_bytes(),
                                        )
                                        .unwrap(),
                                    )
                                    .index(
                                        packed::Uint32::from_slice(
                                            &dep.out_point.index.value().to_le_bytes(),
                                        )
                                        .unwrap(),
                                    )
                                    .build(),
                            )
                            .dep_type(match dep.dep_type {
                                DepType::Code => packed::Byte::new(0),
                                DepType::DepGroup => packed::Byte::new(1),
                            })
                            .build()
                    })
                    .collect::<Vec<_>>()
                    .pack(),
            )
            .inputs(
                tx.inputs
                    .iter()
                    .map(|input| {
                        packed::CellInput::new_builder()
                            .previous_output(
                                packed::OutPoint::new_builder()
                                    .tx_hash(
                                        packed::Byte32::from_slice(
                                            input.previous_output.tx_hash.as_bytes(),
                                        )
                                        .unwrap(),
                                    )
                                    .index(
                                        packed::Uint32::from_slice(
                                            &input.previous_output.index.value().to_le_bytes(),
                                        )
                                        .unwrap(),
                                    )
                                    .build(),
                            )
                            .since(
                                packed::Uint64::from_slice(&input.since.value().to_le_bytes())
                                    .unwrap(),
                            )
                            .build()
                    })
                    .collect::<Vec<_>>()
                    .pack(),
            )
            .outputs(
                tx.outputs
                    .iter()
                    .map(|output| {
                        let lock = packed::Script::new_builder()
                            .code_hash(
                                packed::Byte32::from_slice(output.lock.code_hash.as_bytes())
                                    .unwrap(),
                            )
                            .hash_type(match output.lock.hash_type {
                                ckb_jsonrpc_types::ScriptHashType::Data => packed::Byte::new(0),
                                ckb_jsonrpc_types::ScriptHashType::Type => packed::Byte::new(1),
                                ckb_jsonrpc_types::ScriptHashType::Data1 => packed::Byte::new(2),
                                ckb_jsonrpc_types::ScriptHashType::Data2 => packed::Byte::new(4),
                                _ => packed::Byte::new(1),
                            })
                            .args(output.lock.args.as_bytes().to_vec().pack())
                            .build();

                        let type_opt = if let Some(ref type_script) = output.type_ {
                            packed::ScriptOpt::new_builder()
                                .set(Some(
                                    packed::Script::new_builder()
                                        .code_hash(
                                            packed::Byte32::from_slice(
                                                type_script.code_hash.as_bytes(),
                                            )
                                            .unwrap(),
                                        )
                                        .hash_type(match type_script.hash_type {
                                            ckb_jsonrpc_types::ScriptHashType::Data => {
                                                packed::Byte::new(0)
                                            }
                                            ckb_jsonrpc_types::ScriptHashType::Type => {
                                                packed::Byte::new(1)
                                            }
                                            ckb_jsonrpc_types::ScriptHashType::Data1 => {
                                                packed::Byte::new(2)
                                            }
                                            ckb_jsonrpc_types::ScriptHashType::Data2 => {
                                                packed::Byte::new(4)
                                            }
                                            _ => packed::Byte::new(1),
                                        })
                                        .args(type_script.args.as_bytes().to_vec().pack())
                                        .build(),
                                ))
                                .build()
                        } else {
                            packed::ScriptOpt::new_builder().build()
                        };

                        packed::CellOutput::new_builder()
                            .capacity(
                                packed::Uint64::from_slice(&output.capacity.value().to_le_bytes())
                                    .unwrap(),
                            )
                            .lock(lock)
                            .type_(type_opt)
                            .build()
                    })
                    .collect::<Vec<_>>()
                    .pack(),
            )
            .outputs_data(
                tx.outputs_data
                    .iter()
                    .map(|d| d.as_bytes().to_vec().pack())
                    .collect::<Vec<packed::Bytes>>()
                    .pack(),
            )
            .build();

        let hash = blake2b_256(raw_tx.as_slice());
        H256::from_slice(&hash).unwrap()
    }

    /// Sign the transaction with the miner key.
    fn sign_transaction(&self, tx: Transaction, tx_hash: &H256) -> Result<Transaction, String> {
        let secp = Secp256k1::new();

        // Build witness args with placeholder for signature
        let placeholder_witness = packed::WitnessArgs::new_builder()
            .lock(
                packed::BytesOpt::new_builder()
                    .set(Some(vec![0u8; 65].pack()))
                    .build(),
            )
            .build();

        // Calculate message to sign
        // message = hash(tx_hash || witness_args_length || witness_args || other_witnesses_length || other_witnesses)
        let mut hasher_data = Vec::new();
        hasher_data.extend_from_slice(tx_hash.as_bytes());

        let witness_bytes = placeholder_witness.as_bytes();
        hasher_data.extend_from_slice(&(witness_bytes.len() as u64).to_le_bytes());
        hasher_data.extend_from_slice(&witness_bytes);

        // Add other witnesses (if any)
        for _ in 1..tx.inputs.len() {
            let empty_witness = packed::WitnessArgs::new_builder().build();
            let witness_bytes = empty_witness.as_bytes();
            hasher_data.extend_from_slice(&(witness_bytes.len() as u64).to_le_bytes());
            hasher_data.extend_from_slice(&witness_bytes);
        }

        let message_hash = blake2b_256(&hasher_data);
        let message = Message::from_digest(message_hash);

        // Sign
        let sig = secp.sign_ecdsa_recoverable(&message, &self.miner_key);
        let (recovery_id, signature_bytes) = sig.serialize_compact();

        // Build actual witness with signature
        let mut signature = signature_bytes.to_vec();
        signature.push(recovery_id.to_i32() as u8);

        let signed_witness = packed::WitnessArgs::new_builder()
            .lock(
                packed::BytesOpt::new_builder()
                    .set(Some(signature.pack()))
                    .build(),
            )
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
