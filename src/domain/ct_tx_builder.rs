//! Transaction builder for confidential token transactions.
//!
//! Builds CKB transactions that transfer CT tokens using Bulletproofs range proofs.

use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{
    CellDep, CellInput, CellOutput, DepType, JsonBytes, OutPoint, Script, Transaction, Uint32,
    Uint64,
};
use ckb_types::H256;
use color_eyre::eyre::{eyre, Result};
use curve25519_dalek_ng::scalar::Scalar;
use secp256k1::{Message, PublicKey, Secp256k1};

use crate::{
    config::Config,
    domain::{
        account::Account,
        cell::CtCell,
        ct::{commit, encrypt_amount, prove_range, random_blinding},
        stealth::{derive_stealth_secret, generate_ephemeral_key},
    },
};

/// Minimum cell capacity in CKB for a CT token cell with stealth-lock.
/// CT cell needs: capacity (8B) + lock (stealth 86B) + type (97B) + data (64B) = 255 bytes
const MIN_CT_CELL_CAPACITY: u64 = 255_00000000;

/// Transaction fee in shannons.
const DEFAULT_TX_FEE: u64 = 100_000;

/// A built CT transaction ready for submission.
#[derive(Debug, Clone)]
pub struct BuiltCtTransaction {
    pub tx: Transaction,
    pub tx_hash: H256,
    /// Output blinding factors (needed for the recipient to verify)
    pub output_blindings: Vec<Scalar>,
}

/// Output specification for a CT transfer.
#[derive(Debug, Clone)]
pub struct CtTxOutput {
    /// Recipient stealth address (66 bytes = view_pub || spend_pub).
    pub stealth_address: Vec<u8>,
    /// Amount to transfer.
    pub amount: u64,
}

/// CT transaction builder.
#[derive(Debug, Clone)]
pub struct CtTxBuilder {
    config: Config,
    token_type_hash: [u8; 32],
    pub inputs: Vec<CtCell>,
    outputs: Vec<CtTxOutput>,
    fee: u64,
}

impl CtTxBuilder {
    pub fn new(config: Config, token_type_hash: [u8; 32]) -> Self {
        Self {
            config,
            token_type_hash,
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

    /// Add an input CT cell to spend.
    pub fn add_input(mut self, cell: CtCell) -> Self {
        self.inputs.push(cell);
        self
    }

    /// Add multiple input CT cells.
    pub fn add_inputs(mut self, cells: Vec<CtCell>) -> Self {
        self.inputs.extend(cells);
        self
    }

    /// Add an output to send CT tokens to a stealth address.
    pub fn add_output(mut self, stealth_address: Vec<u8>, amount: u64) -> Self {
        self.outputs.push(CtTxOutput {
            stealth_address,
            amount,
        });
        self
    }

    /// Select inputs from available CT cells to cover the required amount.
    pub fn select_inputs(
        mut self,
        available_cells: &[CtCell],
        required_amount: u64,
    ) -> Result<Self> {
        // Filter cells by token type
        let matching_cells: Vec<_> = available_cells
            .iter()
            .filter(|c| c.token_type_hash == self.token_type_hash)
            .cloned()
            .collect();

        let mut selected = Vec::new();
        let mut total_input = 0u64;

        // Simple greedy selection - sort by amount descending
        let mut sorted_cells = matching_cells;
        sorted_cells.sort_by(|a, b| b.amount.cmp(&a.amount));

        for cell in sorted_cells {
            if total_input >= required_amount {
                break;
            }
            total_input += cell.amount;
            selected.push(cell);
        }

        if total_input < required_amount {
            return Err(eyre!(
                "Insufficient CT token balance: have {}, need {}",
                total_input,
                required_amount
            ));
        }

        self.inputs = selected;
        Ok(self)
    }

    /// Build the CT transfer transaction.
    ///
    /// This generates:
    /// - Output commitments with fresh blinding factors
    /// - Bulletproofs range proof
    /// - Encrypted amounts for recipients
    pub fn build(self, sender_account: &Account) -> Result<BuiltCtTransaction> {
        if self.inputs.is_empty() {
            return Err(eyre!("No inputs specified"));
        }

        if self.outputs.is_empty() {
            return Err(eyre!("No outputs specified"));
        }

        let total_input: u64 = self.inputs.iter().map(|c| c.amount).sum();
        let total_output: u64 = self.outputs.iter().map(|o| o.amount).sum();

        if total_input < total_output {
            return Err(eyre!(
                "Insufficient input: {} < {}",
                total_input,
                total_output
            ));
        }

        let change_amount = total_input - total_output;

        // Collect input blinding factors
        let input_blindings: Vec<Scalar> = self
            .inputs
            .iter()
            .map(|c| {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&c.blinding_factor);
                Scalar::from_bytes_mod_order(bytes)
            })
            .collect();

        // Generate output blinding factors
        let mut output_blindings = Vec::new();
        let mut output_amounts = Vec::new();

        for output in &self.outputs {
            output_blindings.push(random_blinding());
            output_amounts.push(output.amount);
        }

        // Add change output if needed
        let has_change = change_amount > 0;
        if has_change {
            output_amounts.push(change_amount);
            // Change blinding: ensure sum(r_in) == sum(r_out)
            let sum_input: Scalar = input_blindings.iter().sum();
            let sum_output: Scalar = output_blindings.iter().sum();
            let change_blinding = sum_input - sum_output;
            output_blindings.push(change_blinding);
        }

        // Generate range proof
        let (range_proof, commitments) = prove_range(&output_amounts, &output_blindings)
            .map_err(|e| eyre!("Failed to generate range proof: {}", e))?;

        // Build cell deps
        let cell_deps = self.build_cell_deps()?;

        // Build inputs
        let inputs = self.build_inputs();

        // Build outputs
        let mut outputs = Vec::new();
        let mut outputs_data = Vec::new();

        for (i, output) in self.outputs.iter().enumerate() {
            let (script, output_data) = self.build_ct_output(
                &output.stealth_address,
                output.amount,
                &output_blindings[i],
                &commitments[i],
            )?;

            outputs.push(CellOutput {
                capacity: Uint64::from(MIN_CT_CELL_CAPACITY),
                lock: script,
                type_: Some(self.build_ct_type_script()?),
            });
            outputs_data.push(JsonBytes::from_vec(output_data));
        }

        // Add change output
        if has_change {
            let change_idx = self.outputs.len();
            let (change_script, change_data) = self.build_ct_change_output(
                sender_account,
                change_amount,
                &output_blindings[change_idx],
                &commitments[change_idx],
            )?;

            outputs.push(CellOutput {
                capacity: Uint64::from(MIN_CT_CELL_CAPACITY),
                lock: change_script,
                type_: Some(self.build_ct_type_script()?),
            });
            outputs_data.push(JsonBytes::from_vec(change_data));
        }

        // Add range proof to witnesses
        let proof_bytes = range_proof.to_bytes();

        // Build transaction
        let tx = Transaction {
            version: Uint32::from(0u32),
            cell_deps,
            header_deps: vec![],
            inputs,
            outputs,
            outputs_data,
            witnesses: vec![JsonBytes::from_vec(proof_bytes); self.inputs.len()],
        };

        let tx_hash = Self::calculate_tx_hash(&tx);

        Ok(BuiltCtTransaction {
            tx,
            tx_hash,
            output_blindings,
        })
    }

    /// Sign the built CT transaction.
    pub fn sign(
        built_tx: BuiltCtTransaction,
        account: &Account,
        input_cells: &[CtCell],
    ) -> Result<Transaction> {
        let secp = Secp256k1::new();
        let message = Message::from_digest(built_tx.tx_hash.0);

        let mut signed_witnesses = Vec::new();

        for (i, cell) in input_cells.iter().enumerate() {
            // Derive the stealth secret key for this input
            let stealth_secret = derive_stealth_secret(
                &cell.lock_script_args,
                &account.view_secret_key(),
                &account.spend_secret_key(),
            )
            .ok_or_else(|| eyre!("Failed to derive stealth secret for input {}", i))?;

            // Sign with recoverable signature
            let sig = secp.sign_ecdsa_recoverable(&message, &stealth_secret);
            let (recovery_id, signature_bytes) = sig.serialize_compact();

            // Build witness: range_proof || signature (64 bytes) || recovery_id (1 byte)
            let range_proof_bytes = built_tx.tx.witnesses[0].as_bytes().to_vec();
            let mut witness_data = range_proof_bytes;
            witness_data.extend_from_slice(&signature_bytes);
            witness_data.push(recovery_id.to_i32() as u8);

            signed_witnesses.push(JsonBytes::from_vec(witness_data));
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

    /// Build a mint transaction (issuer only).
    ///
    /// Mint creates new CT tokens with commitment = amount * G (zero blinding).
    pub fn build_mint(
        config: Config,
        token_type_hash: [u8; 32],
        mint_amount: u64,
        recipient_stealth_address: Vec<u8>,
        _issuer_account: &Account,
    ) -> Result<BuiltCtTransaction> {
        // For minting, we use zero blinding factor
        let blinding = Scalar::zero();
        let _commitment = commit(mint_amount, &blinding);

        // Generate range proof for single output
        let (range_proof, commitments) = prove_range(&[mint_amount], &[blinding])
            .map_err(|e| eyre!("Failed to generate range proof: {}", e))?;

        // Build the output
        let builder = CtTxBuilder::new(config.clone(), token_type_hash);
        let (lock_script, output_data) = builder.build_ct_output(
            &recipient_stealth_address,
            mint_amount,
            &blinding,
            &commitments[0],
        )?;

        let cell_deps = builder.build_cell_deps()?;
        // TODO: Add ct-info cell dep for minting authorization

        let tx = Transaction {
            version: Uint32::from(0u32),
            cell_deps,
            header_deps: vec![],
            inputs: vec![], // Minting has no CT inputs, but needs ct-info cell
            outputs: vec![CellOutput {
                capacity: Uint64::from(MIN_CT_CELL_CAPACITY),
                lock: lock_script,
                type_: Some(builder.build_ct_type_script()?),
            }],
            outputs_data: vec![JsonBytes::from_vec(output_data)],
            witnesses: vec![JsonBytes::from_vec(range_proof.to_bytes())],
        };

        let tx_hash = Self::calculate_tx_hash(&tx);

        Ok(BuiltCtTransaction {
            tx,
            tx_hash,
            output_blindings: vec![blinding],
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

        let stealth_dep = CellDep {
            out_point: OutPoint {
                tx_hash: stealth_lock_hash,
                index: Uint32::from(self.config.cell_deps.stealth_lock.index),
            },
            dep_type: DepType::Code,
        };

        // Add ct-token cell dep
        let ct_token_tx_hash = self
            .config
            .cell_deps
            .ct_token
            .tx_hash
            .trim_start_matches("0x");
        let ct_token_hash = H256::from_slice(&hex::decode(ct_token_tx_hash)?)?;

        let ct_token_dep = CellDep {
            out_point: OutPoint {
                tx_hash: ct_token_hash,
                index: Uint32::from(self.config.cell_deps.ct_token.index),
            },
            dep_type: DepType::Code,
        };

        Ok(vec![stealth_dep, ct_token_dep])
    }

    fn build_inputs(&self) -> Vec<CellInput> {
        self.inputs
            .iter()
            .map(|cell| {
                let tx_hash = H256::from_slice(&cell.out_point[0..32]).expect("valid tx hash");
                let index = u32::from_le_bytes(cell.out_point[32..36].try_into().unwrap());

                CellInput {
                    previous_output: OutPoint {
                        tx_hash,
                        index: Uint32::from(index),
                    },
                    since: Uint64::from(0u64),
                }
            })
            .collect()
    }

    fn build_ct_output(
        &self,
        stealth_address: &[u8],
        amount: u64,
        _blinding: &Scalar,
        commitment: &curve25519_dalek_ng::ristretto::CompressedRistretto,
    ) -> Result<(Script, Vec<u8>)> {
        if stealth_address.len() != 66 {
            return Err(eyre!(
                "Invalid stealth address length: {} (expected 66)",
                stealth_address.len()
            ));
        }

        // Parse view_pub and spend_pub
        let view_pub = PublicKey::from_slice(&stealth_address[0..33])?;
        let spend_pub = PublicKey::from_slice(&stealth_address[33..66])?;

        // Generate ephemeral key and derive one-time address
        let (eph_pub, stealth_pub) = generate_ephemeral_key(&view_pub, &spend_pub);
        let pubkey_hash = blake2b_256(stealth_pub.serialize());

        // Build lock script args
        let mut script_args = Vec::with_capacity(53);
        script_args.extend_from_slice(&eph_pub.serialize());
        script_args.extend_from_slice(&pubkey_hash[0..20]);

        let code_hash = self
            .config
            .contracts
            .stealth_lock_code_hash
            .trim_start_matches("0x");
        let code_hash_bytes = hex::decode(code_hash)?;

        let lock_script = Script {
            code_hash: H256::from_slice(&code_hash_bytes)?,
            hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
            args: JsonBytes::from_vec(script_args.clone()),
        };

        // Encrypt amount using shared secret
        let secp = Secp256k1::new();
        let shared_point = view_pub
            .mul_tweak(&secp, &secp256k1::Scalar::random())
            .map_err(|_| eyre!("ECDH failed"))?;
        let shared_secret = shared_point.serialize();
        let encrypted = encrypt_amount(amount, &shared_secret);

        // Build output data: commitment (32B) || encrypted_amount (32B)
        let mut output_data = Vec::with_capacity(64);
        output_data.extend_from_slice(commitment.as_bytes());
        output_data.extend_from_slice(&encrypted);

        Ok((lock_script, output_data))
    }

    fn build_ct_change_output(
        &self,
        account: &Account,
        amount: u64,
        _blinding: &Scalar,
        commitment: &curve25519_dalek_ng::ristretto::CompressedRistretto,
    ) -> Result<(Script, Vec<u8>)> {
        let view_pub = account.view_public_key();
        let spend_pub = account.spend_public_key();

        // Generate fresh one-time address for change
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

        let lock_script = Script {
            code_hash: H256::from_slice(&code_hash_bytes)?,
            hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
            args: JsonBytes::from_vec(script_args),
        };

        // Encrypt amount for ourselves
        let secp = Secp256k1::new();
        let shared_point = view_pub
            .mul_tweak(&secp, &secp256k1::Scalar::random())
            .map_err(|_| eyre!("ECDH failed"))?;
        let shared_secret = shared_point.serialize();
        let encrypted = encrypt_amount(amount, &shared_secret);

        let mut output_data = Vec::with_capacity(64);
        output_data.extend_from_slice(commitment.as_bytes());
        output_data.extend_from_slice(&encrypted);

        Ok((lock_script, output_data))
    }

    fn build_ct_type_script(&self) -> Result<Script> {
        let code_hash = self
            .config
            .contracts
            .ct_token_code_hash
            .trim_start_matches("0x");
        let code_hash_bytes = hex::decode(code_hash)?;

        Ok(Script {
            code_hash: H256::from_slice(&code_hash_bytes)?,
            hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
            args: JsonBytes::from_vec(self.token_type_hash.to_vec()),
        })
    }

    fn calculate_tx_hash(tx: &Transaction) -> H256 {
        use ckb_types::packed;
        use ckb_types::prelude::*;

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
                                _ => packed::Byte::new(1),
                            })
                            .args(lock_args)
                            .build();

                        let type_opt = output.type_.as_ref().map(|t| {
                            let type_code_hash =
                                packed::Byte32::from_slice(t.code_hash.as_bytes()).unwrap();
                            let type_args: packed::Bytes = t.args.as_bytes().to_vec().pack();
                            packed::Script::new_builder()
                                .code_hash(type_code_hash)
                                .hash_type(match t.hash_type {
                                    ckb_jsonrpc_types::ScriptHashType::Data => packed::Byte::new(0),
                                    ckb_jsonrpc_types::ScriptHashType::Type => packed::Byte::new(1),
                                    ckb_jsonrpc_types::ScriptHashType::Data1 => {
                                        packed::Byte::new(2)
                                    }
                                    ckb_jsonrpc_types::ScriptHashType::Data2 => {
                                        packed::Byte::new(4)
                                    }
                                    _ => packed::Byte::new(1),
                                })
                                .args(type_args)
                                .build()
                        });

                        let mut builder = packed::CellOutput::new_builder()
                            .capacity(
                                packed::Uint64::from_slice(
                                    &(output.capacity.value()).to_le_bytes(),
                                )
                                .unwrap(),
                            )
                            .lock(lock);

                        if let Some(type_script) = type_opt {
                            builder = builder.type_(
                                packed::ScriptOpt::new_builder()
                                    .set(Some(type_script))
                                    .build(),
                            );
                        }

                        builder.build()
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_ct_cell_capacity() {
        // 255 CKB minimum for CT cell with stealth-lock
        assert_eq!(MIN_CT_CELL_CAPACITY, 255_00000000);
    }
}
