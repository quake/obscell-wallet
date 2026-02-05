//! CT Token minting support.
//!
//! Builds genesis and mint transactions for CT tokens via ct-info-type.
//! The ct-info cell is controlled by a stealth-lock, so minting requires the user's
//! secp256k1 private key to sign the transaction.

use bulletproofs::PedersenGens;
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
        ct::{encrypt_amount, prove_range},
        ct_info::{CtInfoData, MINTABLE},
        stealth::{derive_stealth_secret, generate_ephemeral_key},
    },
};

/// Minimum cell capacity in CKB for a CT cell.
const MIN_CT_CELL_CAPACITY: u64 = 142_00000000;

/// A built mint transaction ready for submission.
#[derive(Debug, Clone)]
pub struct BuiltMintTransaction {
    pub tx: Transaction,
    pub tx_hash: H256,
    /// The minted amount.
    pub mint_amount: u64,
    /// Mint commitment (amount * G with zero blinding).
    pub mint_commitment: [u8; 32],
    /// Output blinding factor for the minted CT cell.
    pub output_blinding: Scalar,
    /// Range proof bytes for the minted output.
    pub range_proof_bytes: Vec<u8>,
}

/// Information about the ct-info cell to be consumed.
#[derive(Debug, Clone)]
pub struct CtInfoCellInput {
    /// OutPoint of the ct-info cell (tx_hash || index as 36 bytes).
    pub out_point: Vec<u8>,
    /// Lock script args of the ct-info cell (stealth-lock args: eph_pub || pubkey_hash).
    pub lock_script_args: Vec<u8>,
    /// Current ct-info cell data.
    pub data: CtInfoData,
    /// Cell capacity.
    pub capacity: u64,
}

/// Parameters for a mint transaction.
#[derive(Debug, Clone)]
pub struct MintParams {
    /// CT-Info cell to consume.
    pub ct_info_cell: CtInfoCellInput,
    /// Token ID (32 bytes, from ct-info type script args).
    pub token_id: [u8; 32],
    /// Amount to mint.
    pub mint_amount: u64,
    /// Recipient stealth address (66 bytes = view_pub || spend_pub).
    pub recipient_stealth_address: Vec<u8>,
}

/// Build a CT token mint transaction.
///
/// This creates:
/// 1. ct-info-type cell input -> output (with updated supply)
/// 2. ct-token-type output cell (minted tokens with fresh stealth lock)
/// 3. secp256k1 signature in witness (to unlock ct-info cell's stealth-lock)
/// 4. Mint commitment for ct-token-type verification
/// 5. Range proof for ct-token output
pub fn build_mint_transaction(config: &Config, params: MintParams) -> Result<BuiltMintTransaction> {
    // Validate ct-info data
    if !params.ct_info_cell.data.is_mintable() {
        return Err(eyre!("Token is not mintable (MINTABLE flag not set)"));
    }

    if params
        .ct_info_cell
        .data
        .would_exceed_cap(params.mint_amount as u128)
    {
        return Err(eyre!(
            "Mint would exceed supply cap: {} + {} > {}",
            params.ct_info_cell.data.total_supply,
            params.mint_amount,
            params.ct_info_cell.data.supply_cap
        ));
    }

    // Parse ct-info out point
    if params.ct_info_cell.out_point.len() != 36 {
        return Err(eyre!(
            "Invalid ct-info out_point length: {} (expected 36)",
            params.ct_info_cell.out_point.len()
        ));
    }
    let ct_info_tx_hash = H256::from_slice(&params.ct_info_cell.out_point[0..32])?;
    let ct_info_index =
        u32::from_le_bytes(params.ct_info_cell.out_point[32..36].try_into().unwrap());

    // Build ct-info type script
    let ct_info_code_hash = config.contracts.ct_info_code_hash.trim_start_matches("0x");
    let ct_info_code_hash_bytes = hex::decode(ct_info_code_hash)?;

    // Type args: token_id (32) || version (1)
    let mut ct_info_type_args = Vec::with_capacity(33);
    ct_info_type_args.extend_from_slice(&params.token_id);
    ct_info_type_args.push(0); // version 0

    let ct_info_type_script = Script {
        code_hash: H256::from_slice(&ct_info_code_hash_bytes)?,
        hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
        args: JsonBytes::from_vec(ct_info_type_args),
    };

    // Build ct-info lock script (same as input, stealth-lock)
    let stealth_code_hash = config
        .contracts
        .stealth_lock_code_hash
        .trim_start_matches("0x");
    let stealth_code_hash_bytes = hex::decode(stealth_code_hash)?;

    let ct_info_lock_script = Script {
        code_hash: H256::from_slice(&stealth_code_hash_bytes)?,
        hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
        args: JsonBytes::from_vec(params.ct_info_cell.lock_script_args.clone()),
    };

    // Create updated ct-info data with new supply
    let new_ct_info_data = params
        .ct_info_cell
        .data
        .with_minted(params.mint_amount as u128)?;

    // Compute mint commitment (amount * G with zero blinding)
    let pc_gens = PedersenGens::default();
    let mint_scalar = Scalar::from(params.mint_amount);
    let mint_commitment = pc_gens.commit(mint_scalar, Scalar::zero());
    let mint_commitment_bytes = mint_commitment.compress().to_bytes();

    // Generate output blinding factor and range proof for minted output
    let output_blinding = Scalar::zero(); // Mint uses zero blinding for the commitment
    let (range_proof, commitments) = prove_range(&[params.mint_amount], &[output_blinding])
        .map_err(|e| eyre!("Failed to generate range proof: {}", e))?;

    // Build ct-token output
    let (ct_token_lock_script, ct_token_output_data) = build_ct_token_output(
        config,
        &params.recipient_stealth_address,
        params.mint_amount,
        &commitments[0],
    )?;

    // Build ct-token type script
    let ct_token_code_hash = config.contracts.ct_token_code_hash.trim_start_matches("0x");
    let ct_token_code_hash_bytes = hex::decode(ct_token_code_hash)?;
    let ct_token_type_script = Script {
        code_hash: H256::from_slice(&ct_token_code_hash_bytes)?,
        hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
        args: JsonBytes::from_vec(params.token_id.to_vec()),
    };

    // Build cell deps
    let cell_deps = build_mint_cell_deps(config)?;

    // Build inputs
    let ct_info_input = CellInput {
        previous_output: OutPoint {
            tx_hash: ct_info_tx_hash,
            index: Uint32::from(ct_info_index),
        },
        since: Uint64::from(0u64),
    };

    // Build outputs
    let outputs = vec![
        // Output 0: ct-info-type cell with updated supply
        CellOutput {
            capacity: Uint64::from(params.ct_info_cell.capacity),
            lock: ct_info_lock_script,
            type_: Some(ct_info_type_script),
        },
        // Output 1: ct-token-type cell (minted tokens)
        CellOutput {
            capacity: Uint64::from(MIN_CT_CELL_CAPACITY),
            lock: ct_token_lock_script,
            type_: Some(ct_token_type_script),
        },
    ];

    let outputs_data = vec![
        JsonBytes::from_vec(new_ct_info_data.to_bytes()),
        JsonBytes::from_vec(ct_token_output_data),
    ];

    // Store range proof bytes for later use in signing
    let range_proof_bytes = range_proof.to_bytes();

    // Build transaction (witnesses will be filled after signing)
    let tx = Transaction {
        version: Uint32::from(0u32),
        cell_deps,
        header_deps: vec![],
        inputs: vec![ct_info_input],
        outputs,
        outputs_data,
        witnesses: vec![], // Will be filled in by sign_mint_transaction
    };

    let tx_hash = calculate_tx_hash(&tx);

    Ok(BuiltMintTransaction {
        tx,
        tx_hash,
        mint_amount: params.mint_amount,
        mint_commitment: mint_commitment_bytes,
        output_blinding,
        range_proof_bytes,
    })
}

/// Sign the mint transaction with the account's stealth key.
///
/// The ct-info cell is locked with a stealth-lock, so we need to derive
/// the stealth secret key and sign the transaction.
pub fn sign_mint_transaction(
    built_tx: BuiltMintTransaction,
    account: &Account,
    ct_info_lock_args: &[u8],
) -> Result<Transaction> {
    let secp = Secp256k1::new();
    let message = Message::from_digest(built_tx.tx_hash.0);

    // Derive the stealth secret key for the ct-info cell
    let stealth_secret = derive_stealth_secret(
        ct_info_lock_args,
        &account.view_secret_key(),
        &account.spend_secret_key(),
    )
    .ok_or_else(|| eyre!("Failed to derive stealth secret for ct-info cell"))?;

    // Sign with recoverable signature
    let sig = secp.sign_ecdsa_recoverable(&message, &stealth_secret);
    let (recovery_id, signature_bytes) = sig.serialize_compact();

    // Build witness 0 for ct-info cell:
    // WitnessArgs { lock: signature, input_type: None, output_type: mint_commitment }
    let witness0 = build_witness_args_with_lock_and_output_type(
        &signature_bytes,
        recovery_id.to_i32() as u8,
        &built_tx.mint_commitment,
    );

    // Build witness 1 for ct-token cell:
    // WitnessArgs { lock: None, input_type: mint_commitment, output_type: range_proof }
    // For ct-token-type, we need to provide:
    // - input_type: mint_commitment (32 bytes)
    // - output_type: range_proof
    let witness1 =
        build_witness_args_for_ct_token(&built_tx.mint_commitment, &built_tx.range_proof_bytes);

    Ok(Transaction {
        version: built_tx.tx.version,
        cell_deps: built_tx.tx.cell_deps,
        header_deps: built_tx.tx.header_deps,
        inputs: built_tx.tx.inputs,
        outputs: built_tx.tx.outputs,
        outputs_data: built_tx.tx.outputs_data,
        witnesses: vec![witness0, witness1],
    })
}

fn build_mint_cell_deps(config: &Config) -> Result<Vec<CellDep>> {
    let mut deps = Vec::new();

    // ct-info-type cell dep
    let ct_info_tx_hash = config.cell_deps.ct_info.tx_hash.trim_start_matches("0x");
    let ct_info_hash = H256::from_slice(&hex::decode(ct_info_tx_hash)?)?;
    deps.push(CellDep {
        out_point: OutPoint {
            tx_hash: ct_info_hash,
            index: Uint32::from(config.cell_deps.ct_info.index),
        },
        dep_type: DepType::Code,
    });

    // ct-token-type cell dep
    let ct_token_tx_hash = config.cell_deps.ct_token.tx_hash.trim_start_matches("0x");
    let ct_token_hash = H256::from_slice(&hex::decode(ct_token_tx_hash)?)?;
    deps.push(CellDep {
        out_point: OutPoint {
            tx_hash: ct_token_hash,
            index: Uint32::from(config.cell_deps.ct_token.index),
        },
        dep_type: DepType::Code,
    });

    // stealth-lock cell dep
    let stealth_tx_hash = config
        .cell_deps
        .stealth_lock
        .tx_hash
        .trim_start_matches("0x");
    let stealth_hash = H256::from_slice(&hex::decode(stealth_tx_hash)?)?;
    deps.push(CellDep {
        out_point: OutPoint {
            tx_hash: stealth_hash,
            index: Uint32::from(config.cell_deps.stealth_lock.index),
        },
        dep_type: DepType::Code,
    });

    Ok(deps)
}

fn build_ct_token_output(
    config: &Config,
    stealth_address: &[u8],
    amount: u64,
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

    // Build lock script args: eph_pub (33) || pubkey_hash[0..20] (20)
    let mut script_args = Vec::with_capacity(53);
    script_args.extend_from_slice(&eph_pub.serialize());
    script_args.extend_from_slice(&pubkey_hash[0..20]);

    let code_hash = config
        .contracts
        .stealth_lock_code_hash
        .trim_start_matches("0x");
    let code_hash_bytes = hex::decode(code_hash)?;

    let lock_script = Script {
        code_hash: H256::from_slice(&code_hash_bytes)?,
        hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
        args: JsonBytes::from_vec(script_args),
    };

    // For mint, we use zero blinding, so the encrypted amount can be computed differently
    // But we still encrypt using shared secret for consistency
    // Use deterministic shared secret from ephemeral key for mint
    let shared_secret = blake2b_256(eph_pub.serialize());
    let encrypted = encrypt_amount(amount, &shared_secret);

    // Build output data: commitment (32B) || encrypted_amount (32B)
    let mut output_data = Vec::with_capacity(64);
    output_data.extend_from_slice(commitment.as_bytes());
    output_data.extend_from_slice(&encrypted);

    Ok((lock_script, output_data))
}

fn build_witness_args_with_lock_and_output_type(
    signature: &[u8],
    recovery_id: u8,
    output_type_data: &[u8],
) -> JsonBytes {
    use ckb_types::packed::{Bytes, BytesOpt, WitnessArgs};
    use ckb_types::prelude::*;

    // Lock: signature (64 bytes) || recovery_id (1 byte)
    let mut lock_data = Vec::with_capacity(65);
    lock_data.extend_from_slice(signature);
    lock_data.push(recovery_id);

    let lock_bytes: Bytes = lock_data.pack();
    let output_type_bytes: Bytes = output_type_data.to_vec().pack();

    let witness = WitnessArgs::new_builder()
        .lock(BytesOpt::new_builder().set(Some(lock_bytes)).build())
        .output_type(BytesOpt::new_builder().set(Some(output_type_bytes)).build())
        .build();

    JsonBytes::from_vec(witness.as_bytes().to_vec())
}

fn build_witness_args_for_ct_token(mint_commitment: &[u8], range_proof: &[u8]) -> JsonBytes {
    use ckb_types::packed::{Bytes, BytesOpt, WitnessArgs};
    use ckb_types::prelude::*;

    let input_type_bytes: Bytes = mint_commitment.to_vec().pack();
    let output_type_bytes: Bytes = range_proof.to_vec().pack();

    let witness = WitnessArgs::new_builder()
        .input_type(BytesOpt::new_builder().set(Some(input_type_bytes)).build())
        .output_type(BytesOpt::new_builder().set(Some(output_type_bytes)).build())
        .build();

    JsonBytes::from_vec(witness.as_bytes().to_vec())
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
                                    packed::Byte32::from_slice(dep.out_point.tx_hash.as_bytes())
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
                                ckb_jsonrpc_types::ScriptHashType::Data1 => packed::Byte::new(2),
                                ckb_jsonrpc_types::ScriptHashType::Data2 => packed::Byte::new(4),
                                _ => packed::Byte::new(1),
                            })
                            .args(type_args)
                            .build()
                    });

                    let mut builder = packed::CellOutput::new_builder()
                        .capacity(
                            packed::Uint64::from_slice(&(output.capacity.value()).to_le_bytes())
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

// ============================================================================
// Genesis functionality
// ============================================================================

/// Minimum cell capacity for ct-info cell (57 bytes data + overhead).
const MIN_CT_INFO_CELL_CAPACITY: u64 = 150_00000000;

/// Parameters for creating a new CT token (genesis).
#[derive(Debug, Clone)]
pub struct GenesisParams {
    /// Maximum supply (0 = unlimited).
    pub supply_cap: u128,
    /// Initial flags (typically MINTABLE).
    pub flags: u8,
    /// Issuer's stealth address (66 bytes = view_pub || spend_pub).
    /// The ct-info cell will be locked to this address.
    pub issuer_stealth_address: Vec<u8>,
}

impl Default for GenesisParams {
    fn default() -> Self {
        Self {
            supply_cap: 0, // Unlimited
            flags: MINTABLE,
            issuer_stealth_address: Vec::new(),
        }
    }
}

/// Input cell to fund the genesis transaction.
#[derive(Debug, Clone)]
pub struct FundingCell {
    /// OutPoint of the funding cell (tx_hash || index as 36 bytes).
    pub out_point: Vec<u8>,
    /// Cell capacity in shannons.
    pub capacity: u64,
    /// Lock script args (stealth-lock args).
    pub lock_script_args: Vec<u8>,
}

/// A built genesis transaction ready for signing.
#[derive(Debug, Clone)]
pub struct BuiltGenesisTransaction {
    pub tx: Transaction,
    pub tx_hash: H256,
    /// The generated token ID (from Type ID).
    pub token_id: [u8; 32],
    /// Lock script args for the ct-info cell.
    pub ct_info_lock_args: Vec<u8>,
}

/// Build a CT token genesis transaction.
///
/// This creates:
/// 1. A new ct-info-type cell with initial supply = 0
/// 2. The ct-info cell is locked with a stealth-lock for the issuer
/// 3. Token ID is derived using Type ID mechanism
///
/// The funding cell provides CKB for the ct-info cell capacity.
pub fn build_genesis_transaction(
    config: &Config,
    params: GenesisParams,
    funding_cell: FundingCell,
) -> Result<BuiltGenesisTransaction> {
    // Validate parameters
    if params.issuer_stealth_address.len() != 66 {
        return Err(eyre!(
            "Invalid issuer stealth address length: {} (expected 66)",
            params.issuer_stealth_address.len()
        ));
    }

    if funding_cell.capacity < MIN_CT_INFO_CELL_CAPACITY {
        return Err(eyre!(
            "Insufficient funding: {} < {} required",
            funding_cell.capacity,
            MIN_CT_INFO_CELL_CAPACITY
        ));
    }

    // Parse funding cell out point
    if funding_cell.out_point.len() != 36 {
        return Err(eyre!(
            "Invalid funding out_point length: {} (expected 36)",
            funding_cell.out_point.len()
        ));
    }
    let funding_tx_hash = H256::from_slice(&funding_cell.out_point[0..32])?;
    let funding_index = u32::from_le_bytes(funding_cell.out_point[32..36].try_into().unwrap());

    // Build input
    let funding_input = CellInput {
        previous_output: OutPoint {
            tx_hash: funding_tx_hash.clone(),
            index: Uint32::from(funding_index),
        },
        since: Uint64::from(0u64),
    };

    // Calculate Type ID: blake2b(inputs[0] || output_index)
    // inputs[0] = tx_hash (32) || index (4) || since (8) = 44 bytes
    let mut type_id_input = Vec::with_capacity(48);
    type_id_input.extend_from_slice(funding_tx_hash.as_bytes());
    type_id_input.extend_from_slice(&funding_index.to_le_bytes());
    type_id_input.extend_from_slice(&0u64.to_le_bytes()); // since = 0
    type_id_input.extend_from_slice(&0u64.to_le_bytes()); // output_index = 0
    let token_id = blake2b_256(&type_id_input);

    // Build ct-info type script
    let ct_info_code_hash = config.contracts.ct_info_code_hash.trim_start_matches("0x");
    let ct_info_code_hash_bytes = hex::decode(ct_info_code_hash)?;

    // Type args: token_id (32) || version (1)
    let mut ct_info_type_args = Vec::with_capacity(33);
    ct_info_type_args.extend_from_slice(&token_id);
    ct_info_type_args.push(0); // version 0

    let ct_info_type_script = Script {
        code_hash: H256::from_slice(&ct_info_code_hash_bytes)?,
        hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
        args: JsonBytes::from_vec(ct_info_type_args),
    };

    // Build ct-info lock script (stealth-lock for issuer)
    let stealth_code_hash = config
        .contracts
        .stealth_lock_code_hash
        .trim_start_matches("0x");
    let stealth_code_hash_bytes = hex::decode(stealth_code_hash)?;

    // Generate one-time stealth lock for the issuer
    let view_pub = PublicKey::from_slice(&params.issuer_stealth_address[0..33])?;
    let spend_pub = PublicKey::from_slice(&params.issuer_stealth_address[33..66])?;
    let (eph_pub, stealth_pub) = generate_ephemeral_key(&view_pub, &spend_pub);
    let pubkey_hash = blake2b_256(stealth_pub.serialize());

    // Lock args: eph_pub (33) || pubkey_hash[0..20] (20)
    let mut ct_info_lock_args = Vec::with_capacity(53);
    ct_info_lock_args.extend_from_slice(&eph_pub.serialize());
    ct_info_lock_args.extend_from_slice(&pubkey_hash[0..20]);

    let ct_info_lock_script = Script {
        code_hash: H256::from_slice(&stealth_code_hash_bytes)?,
        hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
        args: JsonBytes::from_vec(ct_info_lock_args.clone()),
    };

    // Build funding cell lock script (same stealth-lock pattern)
    let funding_lock_script = Script {
        code_hash: H256::from_slice(&stealth_code_hash_bytes)?,
        hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
        args: JsonBytes::from_vec(funding_cell.lock_script_args.clone()),
    };

    // Create ct-info data with initial supply = 0
    let ct_info_data = CtInfoData::new(0, params.supply_cap, params.flags);

    // Build cell deps
    let cell_deps = build_genesis_cell_deps(config)?;

    // Build outputs
    let change_capacity = funding_cell
        .capacity
        .saturating_sub(MIN_CT_INFO_CELL_CAPACITY);

    let mut outputs = vec![
        // Output 0: ct-info-type cell
        CellOutput {
            capacity: Uint64::from(MIN_CT_INFO_CELL_CAPACITY),
            lock: ct_info_lock_script,
            type_: Some(ct_info_type_script),
        },
    ];

    let mut outputs_data = vec![JsonBytes::from_vec(ct_info_data.to_bytes())];

    // Add change output if there's remaining capacity
    if change_capacity > 0 {
        outputs.push(CellOutput {
            capacity: Uint64::from(change_capacity),
            lock: funding_lock_script,
            type_: None,
        });
        outputs_data.push(JsonBytes::from_vec(vec![]));
    }

    // Build transaction
    let tx = Transaction {
        version: Uint32::from(0u32),
        cell_deps,
        header_deps: vec![],
        inputs: vec![funding_input],
        outputs,
        outputs_data,
        witnesses: vec![], // Will be filled by sign_genesis_transaction
    };

    let tx_hash = calculate_tx_hash(&tx);

    Ok(BuiltGenesisTransaction {
        tx,
        tx_hash,
        token_id,
        ct_info_lock_args,
    })
}

/// Sign the genesis transaction with the funding cell's stealth key.
pub fn sign_genesis_transaction(
    built_tx: BuiltGenesisTransaction,
    account: &Account,
    funding_lock_args: &[u8],
) -> Result<Transaction> {
    let secp = Secp256k1::new();
    let message = Message::from_digest(built_tx.tx_hash.0);

    // Derive the stealth secret key for the funding cell
    let stealth_secret = derive_stealth_secret(
        funding_lock_args,
        &account.view_secret_key(),
        &account.spend_secret_key(),
    )
    .ok_or_else(|| eyre!("Failed to derive stealth secret for funding cell"))?;

    // Sign with recoverable signature
    let sig = secp.sign_ecdsa_recoverable(&message, &stealth_secret);
    let (recovery_id, signature_bytes) = sig.serialize_compact();

    // Build witness for funding cell
    let witness = build_witness_args_with_lock(&signature_bytes, recovery_id.to_i32() as u8);

    Ok(Transaction {
        version: built_tx.tx.version,
        cell_deps: built_tx.tx.cell_deps,
        header_deps: built_tx.tx.header_deps,
        inputs: built_tx.tx.inputs,
        outputs: built_tx.tx.outputs,
        outputs_data: built_tx.tx.outputs_data,
        witnesses: vec![witness],
    })
}

fn build_genesis_cell_deps(config: &Config) -> Result<Vec<CellDep>> {
    let mut deps = Vec::new();

    // ct-info-type cell dep
    let ct_info_tx_hash = config.cell_deps.ct_info.tx_hash.trim_start_matches("0x");
    let ct_info_hash = H256::from_slice(&hex::decode(ct_info_tx_hash)?)?;
    deps.push(CellDep {
        out_point: OutPoint {
            tx_hash: ct_info_hash,
            index: Uint32::from(config.cell_deps.ct_info.index),
        },
        dep_type: DepType::Code,
    });

    // stealth-lock cell dep
    let stealth_tx_hash = config
        .cell_deps
        .stealth_lock
        .tx_hash
        .trim_start_matches("0x");
    let stealth_hash = H256::from_slice(&hex::decode(stealth_tx_hash)?)?;
    deps.push(CellDep {
        out_point: OutPoint {
            tx_hash: stealth_hash,
            index: Uint32::from(config.cell_deps.stealth_lock.index),
        },
        dep_type: DepType::Code,
    });

    Ok(deps)
}

fn build_witness_args_with_lock(signature: &[u8], recovery_id: u8) -> JsonBytes {
    use ckb_types::packed::{Bytes, BytesOpt, WitnessArgs};
    use ckb_types::prelude::*;

    // Lock: signature (64 bytes) || recovery_id (1 byte)
    let mut lock_data = Vec::with_capacity(65);
    lock_data.extend_from_slice(signature);
    lock_data.push(recovery_id);

    let lock_bytes: Bytes = lock_data.pack();

    let witness = WitnessArgs::new_builder()
        .lock(BytesOpt::new_builder().set(Some(lock_bytes)).build())
        .build();

    JsonBytes::from_vec(witness.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_min_capacities() {
        assert_eq!(MIN_CT_CELL_CAPACITY, 142_00000000);
        assert_eq!(MIN_CT_INFO_CELL_CAPACITY, 150_00000000);
    }
}
