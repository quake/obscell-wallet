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
use ckb_types::{packed, prelude::*, H256};
use color_eyre::eyre::{eyre, Result};
use curve25519_dalek::scalar::Scalar;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

use crate::{
    config::Config,
    domain::{
        account::Account,
        ct::{encrypt_amount, prove_range},
        ct_info::{CtInfoData, MINTABLE},
        stealth::{
            derive_stealth_secret, generate_ephemeral_key,
            generate_ephemeral_key_with_shared_secret,
        },
    },
};

/// Minimum cell capacity in CKB for a CT token cell with stealth-lock.
/// Calculation:
/// - Base: 8 bytes (capacity field)
/// - Lock (stealth-lock): code_hash (32) + hash_type (1) + args (53 = eph_pub 33 + pubkey_hash 20) = 86 bytes
/// - Type (ct-token-type): code_hash (32) + hash_type (1) + args (32 = ct_info_script_hash) = 65 bytes
/// - Data: commitment (32) + encrypted_amount (32) = 64 bytes
///
/// Total: 8 + 86 + 65 + 64 = 223 bytes → 223 CKB
const MIN_CT_CELL_CAPACITY: u64 = 223_00000000;

/// Default transaction fee in shannons (0.001 CKB = 100,000 shannons).
/// This covers the minimum fee rate of 1000 shannons/KB for typical tx sizes.
const DEFAULT_TX_FEE: u64 = 100_000;

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
    /// Funding cell to pay for the new ct-token cell capacity and tx fees.
    pub funding_cell: FundingCell,
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
    // === DIAGNOSTIC LOGGING ===
    // Log contract configuration for troubleshooting version mismatches
    tracing::info!(
        "=== CT Mint Transaction Build ===\n  \
         Token ID: 0x{}\n  \
         Mint amount: {}\n  \
         ct-info supply_cap: {} ({})\n  \
         ct-info total_supply: {}\n  \
         ct-info flags: 0x{:02x} (mintable={})",
        hex::encode(&params.token_id[0..8]),
        params.mint_amount,
        params.ct_info_cell.data.supply_cap,
        if params.ct_info_cell.data.supply_cap == 0 {
            "UNLIMITED"
        } else {
            "limited"
        },
        params.ct_info_cell.data.total_supply,
        params.ct_info_cell.data.flags,
        params.ct_info_cell.data.is_mintable()
    );

    tracing::debug!(
        "Contract config:\n  \
         ct_info_code_hash: {}\n  \
         ct_token_code_hash: {}\n  \
         stealth_lock_code_hash: {}",
        &config.contracts.ct_info_code_hash,
        &config.contracts.ct_token_code_hash,
        &config.contracts.stealth_lock_code_hash
    );

    tracing::debug!(
        "ct-info cell input:\n  \
         out_point: 0x{}\n  \
         capacity: {} CKB\n  \
         lock_script_args: 0x{}",
        hex::encode(&params.ct_info_cell.out_point),
        params.ct_info_cell.capacity as f64 / 100_000_000.0,
        hex::encode(&params.ct_info_cell.lock_script_args)
    );

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

    // Validate mint amount is within 32-bit range (required by bulletproofs range proof)
    // The contract uses 32-bit range proofs, so max value is 2^32 - 1 = 4,294,967,295
    const MAX_RANGE_PROOF_VALUE: u64 = u32::MAX as u64;
    if params.mint_amount > MAX_RANGE_PROOF_VALUE {
        return Err(eyre!(
            "Mint amount {} exceeds maximum allowed value {} (32-bit range proof limit).\n\
             The contract uses 32-bit range proofs, limiting individual transaction amounts to ~4.29 billion.\n\
             To mint larger amounts, split into multiple transactions.",
            params.mint_amount,
            MAX_RANGE_PROOF_VALUE
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
    let mint_commitment = pc_gens.commit(mint_scalar, Scalar::ZERO);
    let mint_commitment_bytes = mint_commitment.compress().to_bytes();

    // Generate output blinding factor and range proof for minted output
    let output_blinding = Scalar::ZERO; // Mint uses zero blinding for the commitment
    let (range_proof, commitments) = prove_range(&[params.mint_amount], &[output_blinding])
        .map_err(|e| eyre!("Failed to generate range proof: {}", e))?;

    // === RANGE PROOF DIAGNOSTIC ===
    // This is critical for debugging InvalidRangeProof errors (error code 9)
    let commitments_match = mint_commitment_bytes == commitments[0].to_bytes();
    tracing::info!(
        "Range proof generated:\n  \
         amount: {}\n  \
         mint_commitment: 0x{}\n  \
         range_proof_commitment: 0x{}\n  \
         commitments_match: {} {}",
        params.mint_amount,
        hex::encode(mint_commitment_bytes),
        hex::encode(commitments[0].as_bytes()),
        commitments_match,
        if commitments_match {
            "(OK)"
        } else {
            "(MISMATCH - will fail verification!)"
        }
    );

    if !commitments_match {
        tracing::error!(
            "CRITICAL: Mint commitment and range proof commitment do not match!\n  \
             This will cause InvalidRangeProof (error 9) on chain.\n  \
             Possible causes:\n  \
             - Bulletproofs library version mismatch with deployed contract\n  \
             - Different Pedersen generator parameters\n  \
             - Blinding factor mismatch"
        );
    }

    // Build ct-token output
    let (ct_token_lock_script, ct_token_output_data) = build_ct_token_output(
        config,
        &params.recipient_stealth_address,
        params.mint_amount,
        &commitments[0],
    )?;

    // Build ct-token type script
    // Args: ct_info_script_hash (32 bytes)
    // The ct-token-type verifies that ct-info-type with matching script hash exists in inputs
    // This prevents token ID spoofing attacks by binding to the exact ct-info cell
    let ct_token_code_hash = config.contracts.ct_token_code_hash.trim_start_matches("0x");
    let ct_token_code_hash_bytes = hex::decode(ct_token_code_hash)?;

    // Calculate ct-info type script hash (blake2b of the packed script)
    let ct_info_script_hash: [u8; 32] = packed::Script::from(ct_info_type_script.clone())
        .calc_script_hash()
        .unpack();

    let ct_token_type_script = Script {
        code_hash: H256::from_slice(&ct_token_code_hash_bytes)?,
        hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
        args: JsonBytes::from_vec(ct_info_script_hash.to_vec()),
    };

    // Build cell deps
    let cell_deps = build_mint_cell_deps(config)?;

    // Parse funding cell out point
    if params.funding_cell.out_point.len() != 36 {
        return Err(eyre!(
            "Invalid funding out_point length: {} (expected 36)",
            params.funding_cell.out_point.len()
        ));
    }
    let funding_tx_hash = H256::from_slice(&params.funding_cell.out_point[0..32])?;
    let funding_index =
        u32::from_le_bytes(params.funding_cell.out_point[32..36].try_into().unwrap());

    // Validate funding cell has enough capacity
    let required_capacity = MIN_CT_CELL_CAPACITY + DEFAULT_TX_FEE;
    if params.funding_cell.capacity < required_capacity {
        return Err(eyre!(
            "Insufficient funding: {} < {} required (CT cell + fee)",
            params.funding_cell.capacity,
            required_capacity
        ));
    }

    // Build inputs: ct-info cell first, then funding cell
    let ct_info_input = CellInput {
        previous_output: OutPoint {
            tx_hash: ct_info_tx_hash,
            index: Uint32::from(ct_info_index),
        },
        since: Uint64::from(0u64),
    };

    let funding_input = CellInput {
        previous_output: OutPoint {
            tx_hash: funding_tx_hash,
            index: Uint32::from(funding_index),
        },
        since: Uint64::from(0u64),
    };

    // Build funding cell lock script (for change output)
    let funding_lock_script = Script {
        code_hash: H256::from_slice(&stealth_code_hash_bytes)?,
        hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
        args: JsonBytes::from_vec(params.funding_cell.lock_script_args.clone()),
    };

    // Calculate change
    let change_capacity = params
        .funding_cell
        .capacity
        .saturating_sub(MIN_CT_CELL_CAPACITY)
        .saturating_sub(DEFAULT_TX_FEE);

    // Build outputs
    let mut outputs = vec![
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

    let ct_token_data_len = ct_token_output_data.len();
    let mut outputs_data = vec![
        JsonBytes::from_vec(new_ct_info_data.to_bytes()),
        JsonBytes::from_vec(ct_token_output_data),
    ];

    // Add change output if there's remaining capacity
    // Stealth-lock change needs: 8 (capacity) + 90 (lock script with 53-byte args) = 98 bytes
    const MIN_STEALTH_CHANGE_CAPACITY: u64 = 100_00000000;
    if change_capacity >= MIN_STEALTH_CHANGE_CAPACITY {
        outputs.push(CellOutput {
            capacity: Uint64::from(change_capacity),
            lock: funding_lock_script,
            type_: None,
        });
        outputs_data.push(JsonBytes::from_vec(vec![]));
    }

    // Store range proof bytes for later use in signing
    let range_proof_bytes = range_proof.to_bytes();

    tracing::debug!(
        "Transaction structure:\n  \
         inputs: {} (ct-info, funding)\n  \
         outputs: {} (ct-info, ct-token{})\n  \
         range_proof_size: {} bytes\n  \
         ct_token_data_size: {} bytes (commitment + encrypted amount)",
        2,
        outputs.len(),
        if outputs.len() > 2 { ", change" } else { "" },
        range_proof_bytes.len(),
        ct_token_data_len
    );

    // Build transaction (witnesses will be filled after signing)
    let tx = Transaction {
        version: Uint32::from(0u32),
        cell_deps,
        header_deps: vec![],
        inputs: vec![ct_info_input, funding_input],
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

/// Sign the mint transaction with the account's stealth keys.
///
/// Both the ct-info cell and funding cell are locked with stealth-locks,
/// so we need to derive the stealth secret keys and sign the transaction.
/// The `spend_key` must be pre-decrypted using the wallet passphrase.
pub fn sign_mint_transaction(
    built_tx: BuiltMintTransaction,
    account: &Account,
    spend_key: &SecretKey,
    ct_info_lock_args: &[u8],
    funding_lock_args: &[u8],
) -> Result<Transaction> {
    let secp = Secp256k1::new();
    let message = Message::from_digest(built_tx.tx_hash.0);

    // Derive the stealth secret key for the ct-info cell (input 0)
    let ct_info_secret =
        derive_stealth_secret(ct_info_lock_args, &account.view_secret_key(), spend_key)
            .ok_or_else(|| eyre!("Failed to derive stealth secret for ct-info cell"))?;

    // Derive the stealth secret key for the funding cell (input 1)
    let funding_secret =
        derive_stealth_secret(funding_lock_args, &account.view_secret_key(), spend_key)
            .ok_or_else(|| eyre!("Failed to derive stealth secret for funding cell"))?;

    // Sign ct-info cell with recoverable signature
    let ct_info_sig = secp.sign_ecdsa_recoverable(&message, &ct_info_secret);
    let (ct_info_recovery_id, ct_info_signature_bytes) = ct_info_sig.serialize_compact();

    // Sign funding cell with recoverable signature
    let funding_sig = secp.sign_ecdsa_recoverable(&message, &funding_secret);
    let (funding_recovery_id, funding_signature_bytes) = funding_sig.serialize_compact();

    // Build witness 0 for ct-info cell (input 0):
    // WitnessArgs { lock: signature, input_type: None, output_type: mint_commitment }
    // The output_type contains mint_commitment for ct-info-type to verify minting
    let witness0 = build_witness_args_with_lock_and_output_type(
        &ct_info_signature_bytes,
        ct_info_recovery_id.to_i32() as u8,
        &built_tx.mint_commitment,
    );

    // Build witness 1 for funding cell (input 1) AND ct-token (output 1):
    // WitnessArgs {
    //   lock: funding signature (for stealth-lock to unlock input 1),
    //   input_type: mint_commitment (for ct-token-type to verify mint),
    //   output_type: range_proof (for ct-token-type to verify range)
    // }
    // Note: ct-token-type uses load_witness_args(0, Source::GroupOutput), which loads
    // witness at the same index as the first output with this type script (output index 1).
    let witness1 = build_witness_args_full(
        &funding_signature_bytes,
        funding_recovery_id.to_i32() as u8,
        &built_tx.mint_commitment,
        &built_tx.range_proof_bytes,
    );

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

    // ckb-auth cell dep (required for stealth-lock signature verification)
    let ckb_auth_tx_hash = config.cell_deps.ckb_auth.tx_hash.trim_start_matches("0x");
    let ckb_auth_hash = H256::from_slice(&hex::decode(ckb_auth_tx_hash)?)?;
    deps.push(CellDep {
        out_point: OutPoint {
            tx_hash: ckb_auth_hash,
            index: Uint32::from(config.cell_deps.ckb_auth.index),
        },
        dep_type: DepType::Code,
    });

    Ok(deps)
}

fn build_ct_token_output(
    config: &Config,
    stealth_address: &[u8],
    amount: u64,
    commitment: &curve25519_dalek::ristretto::CompressedRistretto,
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

    // Generate ephemeral key, derive one-time address, and get shared secret for encryption
    let (eph_pub, stealth_pub, shared_secret) =
        generate_ephemeral_key_with_shared_secret(&view_pub, &spend_pub);
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

    // Encrypt amount using the shared secret from ECDH
    // This allows the recipient to decrypt using their view key
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

/// Build WitnessArgs with lock, input_type, and output_type.
/// Used for witness that serves both input lock verification and output type verification.
fn build_witness_args_full(
    signature: &[u8],
    recovery_id: u8,
    input_type_data: &[u8],
    output_type_data: &[u8],
) -> JsonBytes {
    use ckb_types::packed::{Bytes, BytesOpt, WitnessArgs};
    use ckb_types::prelude::*;

    // Lock: signature (64 bytes) || recovery_id (1 byte)
    let mut lock_data = Vec::with_capacity(65);
    lock_data.extend_from_slice(signature);
    lock_data.push(recovery_id);

    let lock_bytes: Bytes = lock_data.pack();
    let input_type_bytes: Bytes = input_type_data.to_vec().pack();
    let output_type_bytes: Bytes = output_type_data.to_vec().pack();

    let witness = WitnessArgs::new_builder()
        .lock(BytesOpt::new_builder().set(Some(lock_bytes)).build())
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

/// Minimum cell capacity for ct-info cell.
/// Calculation: 8 (capacity) + 90 (stealth-lock) + 70 (ct-info-type) + 57 (data) = 225 bytes
/// Adding buffer for serialization overhead = 230 CKB
const MIN_CT_INFO_CELL_CAPACITY: u64 = 230_00000000;

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

    // Calculate Type ID: blake2b(inputs[0].as_molecule() || output_index)
    // inputs[0] in molecule format = since (8) || tx_hash (32) || index (4) = 44 bytes
    // output_index = 8 bytes (u64 little-endian)
    // Total = 52 bytes
    let mut type_id_input = Vec::with_capacity(52);
    type_id_input.extend_from_slice(&0u64.to_le_bytes()); // since = 0 (comes first in molecule)
    type_id_input.extend_from_slice(funding_tx_hash.as_bytes()); // tx_hash
    type_id_input.extend_from_slice(&funding_index.to_le_bytes()); // index
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

    // Build outputs (accounting for transaction fee)
    let change_capacity = funding_cell
        .capacity
        .saturating_sub(MIN_CT_INFO_CELL_CAPACITY)
        .saturating_sub(DEFAULT_TX_FEE);

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
    // Stealth-lock change needs: 8 (capacity) + 90 (lock script with 53-byte args) = 98 bytes
    const MIN_STEALTH_CHANGE_CAPACITY: u64 = 100_00000000;
    if change_capacity >= MIN_STEALTH_CHANGE_CAPACITY {
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
/// The `spend_key` must be pre-decrypted using the wallet passphrase.
pub fn sign_genesis_transaction(
    built_tx: BuiltGenesisTransaction,
    account: &Account,
    spend_key: &SecretKey,
    funding_lock_args: &[u8],
) -> Result<Transaction> {
    let secp = Secp256k1::new();
    let message = Message::from_digest(built_tx.tx_hash.0);

    // Derive the stealth secret key for the funding cell
    let stealth_secret =
        derive_stealth_secret(funding_lock_args, &account.view_secret_key(), spend_key)
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

    // ckb-auth cell dep (required for stealth-lock signature verification)
    let ckb_auth_tx_hash = config.cell_deps.ckb_auth.tx_hash.trim_start_matches("0x");
    let ckb_auth_hash = H256::from_slice(&hex::decode(ckb_auth_tx_hash)?)?;
    deps.push(CellDep {
        out_point: OutPoint {
            tx_hash: ckb_auth_hash,
            index: Uint32::from(config.cell_deps.ckb_auth.index),
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
        // 223 CKB for CT cell (reduced from 255 after type args changed from 64B to 32B)
        assert_eq!(MIN_CT_CELL_CAPACITY, 223_00000000);
        assert_eq!(MIN_CT_INFO_CELL_CAPACITY, 230_00000000);
    }
}
