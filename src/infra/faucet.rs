//! Faucet for dev mode.
//!
//! Transfers CKB from the devnet miner address to stealth addresses.

use ckb_hash::{blake2b_256, new_blake2b};
use ckb_jsonrpc_types::{
    CellDep, CellInput, CellOutput, DepType, JsonBytes, OutPoint, Script, Transaction, Uint32,
    Uint64,
};
use ckb_sdk::rpc::ckb_indexer::{Order, ScriptType, SearchKey, SearchMode};
use ckb_sdk::CkbRpcClient;
use ckb_types::packed;
use ckb_types::prelude::*;
use ckb_types::H256;
use color_eyre::eyre::{eyre, Result};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

/// SECP256K1 Blake160 Sighash All lock code hash.
pub const SIGHASH_ALL_CODE_HASH: &str =
    "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";

/// Default transaction fee in shannons (0.001 CKB).
const DEFAULT_FEE_SHANNONS: u64 = 100_000;

/// Minimum cell capacity in shannons (61 CKB).
const MIN_CELL_CAPACITY_SHANNONS: u64 = 61_00000000;

/// Faucet for transferring CKB to stealth addresses.
pub struct Faucet {
    client: CkbRpcClient,
    miner_key: SecretKey,
    miner_lock_args: [u8; 20],
}

impl Faucet {
    /// Create a new faucet.
    pub fn new(rpc_url: &str, miner_key: SecretKey, miner_lock_args: [u8; 20]) -> Self {
        let client = CkbRpcClient::new(rpc_url);
        Self {
            client,
            miner_key,
            miner_lock_args,
        }
    }

    /// Derive lock args from a secret key.
    pub fn derive_lock_args(secret_key: &SecretKey) -> [u8; 20] {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, secret_key);
        let pubkey_hash = blake2b_256(public_key.serialize());
        let mut lock_args = [0u8; 20];
        lock_args.copy_from_slice(&pubkey_hash[0..20]);
        lock_args
    }

    /// Get total miner balance in shannons.
    pub fn get_miner_balance(&self) -> Result<u64> {
        let cells = self.get_miner_cells()?;
        let total: u64 = cells.iter().map(|(_, capacity)| capacity).sum();
        Ok(total)
    }

    /// Transfer CKB to a stealth lock address.
    ///
    /// `stealth_lock_args` is the 53-byte args for stealth lock.
    /// `stealth_lock_code_hash` is the code_hash of the deployed stealth-lock contract.
    /// `amount` is in shannons (1 CKB = 100_000_000 shannons).
    pub fn transfer_to_stealth(
        &self,
        stealth_lock_args: &[u8],
        stealth_lock_code_hash: &H256,
        amount: u64,
    ) -> Result<H256> {
        // Get miner cells
        let miner_cells = self.get_miner_cells()?;
        if miner_cells.is_empty() {
            return Err(eyre!("No miner cells available for transfer"));
        }

        let fee = DEFAULT_FEE_SHANNONS;
        let min_cell_capacity = MIN_CELL_CAPACITY_SHANNONS;

        if amount < min_cell_capacity {
            return Err(eyre!(
                "Amount too small: {} shannons (min {} shannons)",
                amount,
                min_cell_capacity
            ));
        }

        // Select inputs
        let mut selected_inputs = Vec::new();
        let mut total_input: u64 = 0;

        for cell in &miner_cells {
            if total_input >= amount + fee + min_cell_capacity {
                break;
            }
            total_input += cell.1;
            selected_inputs.push(cell.clone());
        }

        if total_input < amount + fee {
            return Err(eyre!(
                "Insufficient balance: need {} CKB, have {} CKB",
                (amount + fee) / 100_000_000,
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

        // Build stealth lock script
        let stealth_lock = Script {
            code_hash: stealth_lock_code_hash.clone(),
            hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
            args: JsonBytes::from_vec(stealth_lock_args.to_vec()),
        };

        let miner_lock = self.build_miner_lock();

        let mut outputs = vec![CellOutput {
            capacity: Uint64::from(amount),
            lock: stealth_lock,
            type_: None,
        }];

        let mut outputs_data = vec![JsonBytes::default()];

        // Add change
        let change_amount = total_input - amount - fee;
        if change_amount >= min_cell_capacity {
            outputs.push(CellOutput {
                capacity: Uint64::from(change_amount),
                lock: miner_lock,
                type_: None,
            });
            outputs_data.push(JsonBytes::default());
        }

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

        // Sign and send
        let tx_hash = self.calculate_tx_hash(&tx);
        let signed_tx = self.sign_transaction(tx, &tx_hash)?;

        let sent_hash = self
            .client
            .send_transaction(signed_tx, None)
            .map_err(|e| eyre!("Failed to send stealth transfer tx: {}", e))?;

        Ok(sent_hash)
    }

    /// Get the sighash_all dep group out point from genesis.
    fn get_sighash_dep_group(&self) -> Result<OutPoint> {
        use ckb_jsonrpc_types::BlockNumber;

        // Get the genesis block
        let genesis = self
            .client
            .get_block_by_number(BlockNumber::from(0u64))
            .map_err(|e| eyre!("Failed to get genesis block: {}", e))?
            .ok_or_else(|| eyre!("Genesis block not found"))?;

        // The dep group is in the second transaction (index 1), output 0
        if genesis.transactions.len() < 2 {
            return Err(eyre!("Genesis block doesn't have dep group transaction"));
        }

        let dep_group_tx = &genesis.transactions[1];
        Ok(OutPoint {
            tx_hash: dep_group_tx.hash.clone(),
            index: Uint32::from(0u32), // secp256k1_blake160_sighash_all dep group at index 0
        })
    }

    /// Get cells owned by the miner.
    fn get_miner_cells(&self) -> Result<Vec<(OutPoint, u64)>> {
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
            .map_err(|e| eyre!("Failed to get miner cells: {}", e))?;

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

    /// Calculate transaction hash.
    fn calculate_tx_hash(&self, tx: &Transaction) -> H256 {
        // Convert to packed::Transaction and use its calc_tx_hash method
        let packed_tx: packed::Transaction = tx.clone().into();
        H256::from_slice(packed_tx.calc_tx_hash().as_slice()).unwrap()
    }

    /// Sign the transaction.
    fn sign_transaction(&self, tx: Transaction, tx_hash: &H256) -> Result<Transaction> {
        let secp = Secp256k1::new();

        // Build witness args with placeholder (65 bytes for recoverable signature)
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
        for i in 1..tx.inputs.len() {
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
