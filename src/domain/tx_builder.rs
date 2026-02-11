//! Transaction builder for stealth address transactions.
//!
//! Builds CKB transactions that send to stealth lock scripts, handling
//! input selection, change outputs, and signing with derived stealth keys.

use std::str::FromStr;

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{
    CellDep, CellInput, CellOutput, DepType, JsonBytes, OutPoint, Script, Transaction, Uint32,
    Uint64,
};
use ckb_sdk::Address;
use ckb_types::H256;
use color_eyre::eyre::{eyre, Result};
use secp256k1::{Message, PublicKey, Secp256k1};

use crate::{
    config::Config,
    domain::{
        account::Account,
        cell::StealthCell,
        stealth::{derive_stealth_secret, generate_ephemeral_key},
    },
};

/// Minimum cell capacity in CKB (61 CKB for a basic stealth lock cell).
/// stealth-lock args = 53 bytes, minimum cell = 61 CKB
const MIN_CELL_CAPACITY: u64 = 61_00000000;

/// Transaction fee in shannons (0.001 CKB default).
const DEFAULT_TX_FEE: u64 = 100_000;

/// A built but unsigned stealth transaction.
#[derive(Debug, Clone)]
pub struct StealthTxBuilder {
    config: Config,
    pub inputs: Vec<StealthCell>,
    outputs: Vec<TxOutput>,
    fee: u64,
}

/// Output type for transaction outputs.
#[derive(Debug, Clone)]
pub enum TxOutput {
    /// Output to a stealth address.
    Stealth {
        /// Recipient stealth address (66 bytes = view_pub || spend_pub).
        stealth_address: Vec<u8>,
        /// Amount in shannons.
        capacity: u64,
    },
    /// Output to a CKB address (secp256k1_blake160_sighash_all lock).
    Ckb {
        /// Lock script for the CKB address.
        lock_script: Script,
        /// Amount in shannons.
        capacity: u64,
    },
}

/// A built transaction ready for submission.
#[derive(Debug, Clone)]
pub struct BuiltTransaction {
    pub tx: Transaction,
    pub tx_hash: H256,
}

impl StealthTxBuilder {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: DEFAULT_TX_FEE,
        }
    }

    /// Set the transaction fee.
    pub fn fee(mut self, fee: u64) -> Self {
        self.fee = fee;
        self
    }

    /// Add an input cell to spend.
    pub fn add_input(mut self, cell: StealthCell) -> Self {
        self.inputs.push(cell);
        self
    }

    /// Add multiple input cells.
    pub fn add_inputs(mut self, cells: Vec<StealthCell>) -> Self {
        self.inputs.extend(cells);
        self
    }

    /// Add an output to send to a stealth address.
    ///
    /// `stealth_address` should be 66 bytes (compressed view_pub || spend_pub).
    pub fn add_output(mut self, stealth_address: Vec<u8>, capacity: u64) -> Self {
        self.outputs.push(TxOutput::Stealth {
            stealth_address,
            capacity,
        });
        self
    }

    /// Add an output to send to a CKB address.
    ///
    /// `ckb_address` should be a valid CKB address string (ckb1.../ckt1...).
    pub fn add_ckb_output(mut self, ckb_address: &str) -> Result<(Self, u64)> {
        let address =
            Address::from_str(ckb_address).map_err(|e| eyre!("Invalid CKB address: {}", e))?;
        let payload = address.payload();

        // Convert payload to lock script
        let lock_script: Script = Script::from(ckb_types::packed::Script::from(payload));

        // Calculate minimum capacity for this lock script
        // Lock script overhead: 8 (capacity) + lock_script_size
        // Lock script size = 1 (code_hash len prefix) + 32 (code_hash) + 1 (hash_type) + 4 (args len prefix) + args.len()
        let args_len = lock_script.args.len();
        let min_capacity = (8 + 32 + 1 + args_len as u64) * 100_000_000; // In shannons

        self.outputs.push(TxOutput::Ckb {
            lock_script,
            capacity: min_capacity, // Will be set properly later
        });

        Ok((self, min_capacity))
    }

    /// Add an output to send to a CKB address with a specific capacity.
    pub fn add_ckb_output_with_capacity(
        mut self,
        ckb_address: &str,
        capacity: u64,
    ) -> Result<Self> {
        let address =
            Address::from_str(ckb_address).map_err(|e| eyre!("Invalid CKB address: {}", e))?;
        let payload = address.payload();

        // Convert payload to lock script
        let lock_script: Script = Script::from(ckb_types::packed::Script::from(payload));

        self.outputs.push(TxOutput::Ckb {
            lock_script,
            capacity,
        });

        Ok(self)
    }

    /// Select inputs from available cells to cover the required amount.
    pub fn select_inputs(
        mut self,
        available_cells: &[StealthCell],
        required_amount: u64,
    ) -> Result<Self> {
        let total_needed = required_amount + self.fee + MIN_CELL_CAPACITY; // Need extra for change

        let mut selected = Vec::new();
        let mut total_input = 0u64;

        // Simple greedy selection - sort by capacity descending
        let mut sorted_cells: Vec<_> = available_cells.to_vec();
        sorted_cells.sort_by(|a, b| b.capacity.cmp(&a.capacity));

        for cell in sorted_cells {
            if total_input >= total_needed {
                break;
            }
            total_input += cell.capacity;
            selected.push(cell);
        }

        if total_input < required_amount + self.fee {
            return Err(eyre!(
                "Insufficient balance: have {} shannons, need {} + {} fee",
                total_input,
                required_amount,
                self.fee
            ));
        }

        self.inputs = selected;
        Ok(self)
    }

    /// Build the transaction, creating outputs and change.
    ///
    /// `sender_account` is used to create the change output back to the sender.
    pub fn build(self, sender_account: &Account) -> Result<BuiltTransaction> {
        if self.inputs.is_empty() {
            return Err(eyre!("No inputs specified"));
        }

        if self.outputs.is_empty() {
            return Err(eyre!("No outputs specified"));
        }

        let total_input: u64 = self.inputs.iter().map(|c| c.capacity).sum();
        let total_output: u64 = self
            .outputs
            .iter()
            .map(|o| match o {
                TxOutput::Stealth { capacity, .. } => *capacity,
                TxOutput::Ckb { capacity, .. } => *capacity,
            })
            .sum();

        if total_input < total_output + self.fee {
            return Err(eyre!(
                "Insufficient input: {} < {} + {} fee",
                total_input,
                total_output,
                self.fee
            ));
        }

        let change_amount = total_input - total_output - self.fee;

        // Build cell deps
        let cell_deps = self.build_cell_deps()?;

        // Build inputs (with validation)
        let inputs = self.build_inputs()?;

        // Build outputs
        let mut outputs = Vec::new();
        let mut outputs_data = Vec::new();

        // Add recipient outputs
        for output in &self.outputs {
            match output {
                TxOutput::Stealth {
                    stealth_address,
                    capacity,
                } => {
                    let (script, _script_args) =
                        self.build_stealth_output_script(stealth_address)?;
                    outputs.push(CellOutput {
                        capacity: Uint64::from(*capacity),
                        lock: script,
                        type_: None,
                    });
                }
                TxOutput::Ckb {
                    lock_script,
                    capacity,
                } => {
                    outputs.push(CellOutput {
                        capacity: Uint64::from(*capacity),
                        lock: lock_script.clone(),
                        type_: None,
                    });
                }
            }
            outputs_data.push(JsonBytes::default());
        }

        // Add change output if there's enough for a cell
        if change_amount >= MIN_CELL_CAPACITY {
            let change_script = self.build_change_script(sender_account)?;
            outputs.push(CellOutput {
                capacity: Uint64::from(change_amount),
                lock: change_script,
                type_: None,
            });
            outputs_data.push(JsonBytes::default());
        } else if change_amount > 0 {
            // If change is too small, add it to the fee (dust collection)
            // This is fine for privacy since we're not creating a tiny output
        }

        // Build the transaction skeleton
        let tx = Transaction {
            version: Uint32::from(0u32),
            cell_deps,
            header_deps: vec![],
            inputs,
            outputs,
            outputs_data,
            witnesses: vec![JsonBytes::default(); self.inputs.len()],
        };

        // Calculate tx hash (without witnesses for signing)
        let tx_hash = Self::calculate_tx_hash(&tx);

        Ok(BuiltTransaction { tx, tx_hash })
    }

    /// Sign the built transaction with the account's keys.
    pub fn sign(
        built_tx: BuiltTransaction,
        account: &Account,
        input_cells: &[StealthCell],
    ) -> Result<Transaction> {
        let secp = Secp256k1::new();
        let message = Message::from_digest(built_tx.tx_hash.0);

        let mut signed_witnesses = Vec::new();

        for (i, cell) in input_cells.iter().enumerate() {
            // Derive the stealth secret key for this input
            let stealth_secret = derive_stealth_secret(
                &cell.stealth_script_args,
                &account.view_secret_key(),
                &account.spend_secret_key(),
            )
            .ok_or_else(|| eyre!("Failed to derive stealth secret for input {}", i))?;

            // Sign with recoverable signature
            let sig = secp.sign_ecdsa_recoverable(&message, &stealth_secret);
            let (recovery_id, signature_bytes) = sig.serialize_compact();

            // Build witness: signature (64 bytes) || recovery_id (1 byte)
            let mut witness_data = signature_bytes.to_vec();
            witness_data.push(recovery_id.to_i32() as u8);

            // Wrap in WitnessArgs format
            let witness_args = Self::build_witness_args(witness_data);
            signed_witnesses.push(JsonBytes::from_vec(witness_args));
        }

        Ok(Transaction {
            version: built_tx.tx.version,
            cell_deps: built_tx.tx.cell_deps,
            header_deps: built_tx.tx.header_deps,
            inputs: built_tx.tx.inputs,
            outputs: built_tx.tx.outputs,
            outputs_data: built_tx.tx.outputs_data,
            witnesses: signed_witnesses,
        })
    }

    fn build_cell_deps(&self) -> Result<Vec<CellDep>> {
        let stealth_lock_tx_hash = self
            .config
            .cell_deps
            .stealth_lock
            .tx_hash
            .trim_start_matches("0x");
        let stealth_lock_hash = H256::from_slice(&hex::decode(stealth_lock_tx_hash)?)?;

        let ckb_auth_tx_hash = self
            .config
            .cell_deps
            .ckb_auth
            .tx_hash
            .trim_start_matches("0x");
        let ckb_auth_hash = H256::from_slice(&hex::decode(ckb_auth_tx_hash)?)?;

        let stealth_dep = CellDep {
            out_point: OutPoint {
                tx_hash: stealth_lock_hash.clone(),
                index: Uint32::from(self.config.cell_deps.stealth_lock.index),
            },
            dep_type: DepType::Code,
        };

        let ckb_auth_dep = CellDep {
            out_point: OutPoint {
                tx_hash: ckb_auth_hash.clone(),
                index: Uint32::from(self.config.cell_deps.ckb_auth.index),
            },
            dep_type: DepType::Code,
        };

        // Avoid duplicate cell deps
        if stealth_lock_hash == ckb_auth_hash
            && self.config.cell_deps.stealth_lock.index == self.config.cell_deps.ckb_auth.index
        {
            Ok(vec![stealth_dep])
        } else {
            Ok(vec![stealth_dep, ckb_auth_dep])
        }
    }

    fn build_inputs(&self) -> Result<Vec<CellInput>> {
        let mut inputs = Vec::with_capacity(self.inputs.len());

        for (i, cell) in self.inputs.iter().enumerate() {
            // Validate out_point length
            if cell.out_point.len() != 36 {
                return Err(eyre!(
                    "Input {}: Invalid out_point length {} (expected 36 bytes)",
                    i,
                    cell.out_point.len()
                ));
            }

            // Parse out_point from cell (tx_hash: 32 bytes, index: 4 bytes LE)
            let tx_hash_bytes = &cell.out_point[0..32];
            let index = u32::from_le_bytes(cell.out_point[32..36].try_into().unwrap());

            // Validate tx_hash is not all zeros - this indicates corrupted cell data
            let is_zero_hash = tx_hash_bytes.iter().all(|&b| b == 0);
            if is_zero_hash {
                return Err(eyre!(
                    "Input {}: Cell has zero tx_hash! This indicates corrupted cell data. \
                    OutPoint: 0x{} (index {}). \
                    Please run a Full Rescan (press 'R' on Accounts tab) to refresh cell data. \
                    If the problem persists, check that your devnet config has valid contract addresses.",
                    i,
                    hex::encode(&cell.out_point),
                    index
                ));
            }

            let tx_hash = H256::from_slice(tx_hash_bytes)?;

            inputs.push(CellInput {
                previous_output: OutPoint {
                    tx_hash,
                    index: Uint32::from(index),
                },
                since: Uint64::from(0u64),
            });
        }

        Ok(inputs)
    }

    /// Build a stealth lock script for an output.
    ///
    /// Returns (Script, script_args as bytes).
    fn build_stealth_output_script(&self, stealth_address: &[u8]) -> Result<(Script, Vec<u8>)> {
        if stealth_address.len() != 66 {
            return Err(eyre!(
                "Invalid stealth address length: {} (expected 66 bytes)",
                stealth_address.len()
            ));
        }

        // Parse view_pub and spend_pub from stealth address
        let view_pub = PublicKey::from_slice(&stealth_address[0..33])?;
        let spend_pub = PublicKey::from_slice(&stealth_address[33..66])?;

        // Generate ephemeral key and derive one-time address
        let (eph_pub, stealth_pub) = generate_ephemeral_key(&view_pub, &spend_pub);
        let pubkey_hash = blake2b_256(stealth_pub.serialize());

        // Build script args: eph_pub (33 bytes) || pubkey_hash[0..20] (20 bytes) = 53 bytes
        let mut script_args = Vec::with_capacity(53);
        script_args.extend_from_slice(&eph_pub.serialize());
        script_args.extend_from_slice(&pubkey_hash[0..20]);

        let code_hash = self
            .config
            .contracts
            .stealth_lock_code_hash
            .trim_start_matches("0x");
        let code_hash_bytes = hex::decode(code_hash)?;

        let script = Script {
            code_hash: H256::from_slice(&code_hash_bytes)?,
            hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
            args: JsonBytes::from_vec(script_args.clone()),
        };

        Ok((script, script_args))
    }

    /// Build a change output script using the sender's stealth address.
    fn build_change_script(&self, account: &Account) -> Result<Script> {
        let view_pub = account.view_public_key();
        let spend_pub = account.spend_public_key();

        // Generate a fresh one-time address for change
        let (eph_pub, stealth_pub) = generate_ephemeral_key(&view_pub, &spend_pub);
        let pubkey_hash = blake2b_256(stealth_pub.serialize());

        let mut script_args = Vec::with_capacity(53);
        script_args.extend_from_slice(&eph_pub.serialize());
        script_args.extend_from_slice(&pubkey_hash[0..20]);

        let code_hash = self
            .config
            .contracts
            .stealth_lock_code_hash
            .trim_start_matches("0x");
        let code_hash_bytes = hex::decode(code_hash)?;

        Ok(Script {
            code_hash: H256::from_slice(&code_hash_bytes)?,
            hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
            args: JsonBytes::from_vec(script_args),
        })
    }

    /// Calculate the transaction hash for signing.
    fn calculate_tx_hash(tx: &Transaction) -> H256 {
        use ckb_types::packed;
        use ckb_types::prelude::*;

        // Convert to packed format for hashing
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
                                packed::Uint64::from_slice(&(input.since.value()).to_le_bytes())
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
                        let lock_code_hash =
                            packed::Byte32::from_slice(output.lock.code_hash.as_bytes()).unwrap();
                        let lock_args: packed::Bytes = output.lock.args.as_bytes().to_vec().pack();
                        let lock = packed::Script::new_builder()
                            .code_hash(lock_code_hash)
                            .hash_type(match output.lock.hash_type {
                                ckb_jsonrpc_types::ScriptHashType::Data => packed::Byte::new(0),
                                ckb_jsonrpc_types::ScriptHashType::Type => packed::Byte::new(1),
                                ckb_jsonrpc_types::ScriptHashType::Data1 => packed::Byte::new(2),
                                ckb_jsonrpc_types::ScriptHashType::Data2 => packed::Byte::new(4),
                                _ => packed::Byte::new(1), // Default to Type for newer variants
                            })
                            .args(lock_args)
                            .build();

                        packed::CellOutput::new_builder()
                            .capacity(
                                packed::Uint64::from_slice(
                                    &(output.capacity.value()).to_le_bytes(),
                                )
                                .unwrap(),
                            )
                            .lock(lock)
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

    /// Build WitnessArgs with lock field containing the signature.
    fn build_witness_args(lock_data: Vec<u8>) -> Vec<u8> {
        use ckb_types::packed;
        use ckb_types::prelude::*;

        let lock_bytes: packed::Bytes = lock_data.pack();
        let witness_args = packed::WitnessArgs::new_builder()
            .lock(
                packed::BytesOpt::new_builder()
                    .set(Some(lock_bytes))
                    .build(),
            )
            .build();

        witness_args.as_bytes().to_vec()
    }
}

/// Parse a stealth address from hex string.
///
/// Input: 132 hex chars (or 0x-prefixed 134 chars).
/// Output: 66 bytes (view_pub || spend_pub).
pub fn parse_stealth_address(hex_str: &str) -> Result<Vec<u8>> {
    let hex_str = hex_str.trim().trim_start_matches("0x");
    if hex_str.len() != 132 {
        return Err(eyre!(
            "Invalid stealth address length: {} (expected 132 hex chars)",
            hex_str.len()
        ));
    }
    let bytes = hex::decode(hex_str)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stealth_address() {
        // Valid address (132 hex chars = 66 bytes)
        let addr = "a".repeat(132);
        let result = parse_stealth_address(&addr);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 66);

        // With 0x prefix
        let addr_prefixed = format!("0x{}", "b".repeat(132));
        let result = parse_stealth_address(&addr_prefixed);
        assert!(result.is_ok());

        // Invalid length
        let invalid = "abc123";
        assert!(parse_stealth_address(invalid).is_err());
    }

    #[test]
    fn test_min_cell_capacity() {
        // 61 CKB minimum for stealth lock cell
        assert_eq!(MIN_CELL_CAPACITY, 61_00000000);
    }
}
