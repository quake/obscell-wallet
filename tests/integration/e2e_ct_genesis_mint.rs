//! End-to-end CT token genesis, mint, and transfer integration tests.
//!
//! Tests the complete CT token lifecycle on-chain:
//! 1. Genesis: Creating a new CT token (ct-info cell)
//! 2. Mint: Minting CT tokens to a stealth address
//! 3. Transfer: Transferring CT tokens between accounts

use ckb_sdk::CkbRpcClient;
use tempfile::TempDir;

use super::devnet::DevNet;
use super::TestEnv;

use obscell_wallet::config::{
    CellDepConfig, CellDepsConfig, Config, ContractConfig, NetworkConfig,
};
use obscell_wallet::domain::account::Account;
use obscell_wallet::domain::ct_info::MINTABLE;
use obscell_wallet::domain::ct_mint::{
    build_genesis_transaction, build_mint_transaction, sign_genesis_transaction,
    sign_mint_transaction, CtInfoCellInput, FundingCell, GenesisParams, MintParams,
};
use obscell_wallet::domain::stealth::generate_ephemeral_key;
use obscell_wallet::infra::scanner::Scanner;
use obscell_wallet::infra::store::Store;

/// Create a test config pointing to the devnet with deployed contracts.
fn create_test_config(env: &TestEnv) -> Config {
    let (stealth_lock_tx_hash, stealth_lock_index) = env.stealth_lock_cell_dep();
    let stealth_type_id_hash = env.stealth_lock_code_hash();
    let (ckb_auth_tx_hash, ckb_auth_index) = env.ckb_auth_cell_dep();
    let ckb_auth_data_hash = env.ckb_auth_data_hash();

    let (ct_info_tx_hash, ct_info_index) = env.ct_info_type_cell_dep();
    let ct_info_type_id_hash = env.ct_info_type_code_hash();

    let (ct_token_tx_hash, ct_token_index) = env.ct_token_type_cell_dep();
    let ct_token_type_id_hash = env.ct_token_type_code_hash();

    Config {
        network: NetworkConfig {
            name: "devnet".to_string(),
            rpc_url: DevNet::RPC_URL.to_string(),
            scan_start_block: 0,
        },
        contracts: ContractConfig {
            stealth_lock_code_hash: format!("0x{}", hex::encode(stealth_type_id_hash.as_bytes())),
            ct_token_code_hash: format!("0x{}", hex::encode(ct_token_type_id_hash.as_bytes())),
            ct_info_code_hash: format!("0x{}", hex::encode(ct_info_type_id_hash.as_bytes())),
            ckb_auth_code_hash: format!("0x{}", hex::encode(ckb_auth_data_hash.as_bytes())),
        },
        cell_deps: CellDepsConfig {
            stealth_lock: CellDepConfig {
                tx_hash: format!("0x{}", hex::encode(stealth_lock_tx_hash.as_bytes())),
                index: stealth_lock_index,
                ..Default::default()
            },
            ckb_auth: CellDepConfig {
                tx_hash: format!("0x{}", hex::encode(ckb_auth_tx_hash.as_bytes())),
                index: ckb_auth_index,
                ..Default::default()
            },
            ct_token: CellDepConfig {
                tx_hash: format!("0x{}", hex::encode(ct_token_tx_hash.as_bytes())),
                index: ct_token_index,
                ..Default::default()
            },
            ct_info: CellDepConfig {
                tx_hash: format!("0x{}", hex::encode(ct_info_tx_hash.as_bytes())),
                index: ct_info_index,
                ..Default::default()
            },
        },
    }
}

/// Create a temporary store for testing.
fn create_temp_store() -> (Store, TempDir) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let store = Store::with_path(temp_dir.path().to_path_buf()).expect("Failed to create store");
    (store, temp_dir)
}

/// Fund an account with stealth cells and return the funding cell info.
fn fund_account_with_stealth(
    env: &TestEnv,
    account: &Account,
    amount: u64,
) -> Result<FundingCell, String> {
    let stealth_code_hash = env.stealth_lock_code_hash();

    // Generate stealth address for the account
    let (eph_pub, stealth_pub) =
        generate_ephemeral_key(&account.view_public_key(), &account.spend_public_key());
    let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
    let mut lock_args = Vec::with_capacity(53);
    lock_args.extend_from_slice(&eph_pub.serialize());
    lock_args.extend_from_slice(&pubkey_hash[0..20]);

    // Send CKB to the stealth address
    let tx_hash = env
        .faucet
        .transfer_to_stealth(&lock_args, &stealth_code_hash, amount)?;

    // Confirm the transaction
    env.generate_blocks(10)?;
    env.wait_for_indexer_sync()?;

    // Build out_point bytes (tx_hash || index as LE u32)
    let mut out_point = Vec::with_capacity(36);
    out_point.extend_from_slice(tx_hash.as_bytes());
    out_point.extend_from_slice(&0u32.to_le_bytes()); // Output index 0

    Ok(FundingCell {
        out_point,
        capacity: amount,
        lock_script_args: lock_args,
    })
}

/// Test CT token genesis - creating a new token.
#[test]
fn test_ct_genesis_creates_token() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (_store, _temp_dir) = create_temp_store();

    // Create issuer account
    let issuer = Account::new_random(0, "Issuer".to_string());
    println!(
        "Issuer stealth address: {}",
        &issuer.stealth_address()[..32]
    );

    // Fund the issuer with a stealth cell (300 CKB for ct-info + change)
    println!("Step 1: Funding issuer account...");
    let funding_amount = 350_00000000u64;
    let funding_cell =
        fund_account_with_stealth(env, &issuer, funding_amount).expect("Funding should succeed");

    println!(
        "Funding cell created: tx_hash=0x{}, capacity={} CKB",
        hex::encode(&funding_cell.out_point[..32]),
        funding_cell.capacity / 100_000_000
    );

    // Build genesis transaction
    println!("Step 2: Building genesis transaction...");
    let issuer_stealth_address = {
        let view_pub = issuer.view_public_key().serialize();
        let spend_pub = issuer.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let genesis_params = GenesisParams {
        supply_cap: 1_000_000_000, // 1 billion max supply
        flags: MINTABLE,
        issuer_stealth_address,
    };

    let built_tx = build_genesis_transaction(&config, genesis_params, funding_cell.clone())
        .expect("Building genesis tx should succeed");

    println!(
        "Genesis tx built: hash=0x{}, token_id=0x{}",
        hex::encode(built_tx.tx_hash.as_bytes()),
        hex::encode(&built_tx.token_id[..8])
    );

    // Sign the transaction
    println!("Step 3: Signing genesis transaction...");
    let signed_tx = sign_genesis_transaction(
        built_tx.clone(),
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &funding_cell.lock_script_args,
    )
    .expect("Signing should succeed");

    // Submit the transaction
    println!("Step 4: Submitting genesis transaction...");
    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let tx_hash = client
        .send_transaction(signed_tx, None)
        .expect("Sending genesis tx should succeed");

    println!("Genesis tx sent: 0x{}", hex::encode(tx_hash.as_bytes()));

    // Confirm the transaction
    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync indexer");

    // Verify the ct-info cell was created
    println!("Step 5: Verifying ct-info cell...");

    // The ct-info cell should be at output index 0 of the genesis tx
    let ct_info_out_point = ckb_jsonrpc_types::OutPoint {
        tx_hash: tx_hash.clone(),
        index: ckb_jsonrpc_types::Uint32::from(0u32),
    };

    let cell_with_status = client
        .get_live_cell(ct_info_out_point, true)
        .expect("Should get cell")
        .cell;

    assert!(cell_with_status.is_some(), "ct-info cell should exist");
    let cell_info = cell_with_status.unwrap();

    // Verify it has ct-info type script
    assert!(
        cell_info.output.type_.is_some(),
        "ct-info cell should have type script"
    );

    let type_script = cell_info.output.type_.as_ref().unwrap();
    let expected_code_hash = env.ct_info_type_code_hash();
    assert_eq!(
        type_script.code_hash, expected_code_hash,
        "Type script code hash should match ct-info-type"
    );

    // Verify the cell data contains initial supply = 0
    let cell_data = cell_info.data.unwrap();
    let data_bytes = cell_data.content.as_bytes();
    assert_eq!(data_bytes.len(), 57, "ct-info data should be 57 bytes");

    let total_supply = u128::from_le_bytes(data_bytes[0..16].try_into().unwrap());
    assert_eq!(total_supply, 0, "Initial supply should be 0");

    let supply_cap = u128::from_le_bytes(data_bytes[16..32].try_into().unwrap());
    assert_eq!(supply_cap, 1_000_000_000, "Supply cap should match");

    let flags = data_bytes[56];
    assert_eq!(flags, MINTABLE, "Flags should be MINTABLE");

    println!(
        "CT token created successfully! Token ID: 0x{}",
        hex::encode(&built_tx.token_id)
    );
    println!("  - Supply cap: {}", supply_cap);
    println!("  - Flags: MINTABLE");
}

/// Test CT token minting to a stealth address.
#[test]
fn test_ct_mint_to_stealth_address() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create issuer and recipient accounts
    let issuer = Account::new_random(0, "Issuer".to_string());
    let recipient = Account::new_random(1, "Recipient".to_string());

    println!("Issuer: {}", &issuer.stealth_address()[..32]);
    println!("Recipient: {}", &recipient.stealth_address()[..32]);

    // Step 1: Create the CT token (genesis)
    println!("Step 1: Creating CT token (genesis)...");
    let funding_amount = 350_00000000u64;
    let funding_cell =
        fund_account_with_stealth(env, &issuer, funding_amount).expect("Funding should succeed");

    let issuer_stealth_address = {
        let view_pub = issuer.view_public_key().serialize();
        let spend_pub = issuer.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let genesis_params = GenesisParams {
        supply_cap: 1_000_000,
        flags: MINTABLE,
        issuer_stealth_address: issuer_stealth_address.clone(),
    };

    let genesis_tx = build_genesis_transaction(&config, genesis_params, funding_cell.clone())
        .expect("Building genesis tx should succeed");

    let token_id = genesis_tx.token_id;
    let ct_info_lock_args = genesis_tx.ct_info_lock_args.clone();

    let signed_genesis = sign_genesis_transaction(
        genesis_tx,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &funding_cell.lock_script_args,
    )
    .expect("Signing genesis should succeed");

    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let genesis_hash = client
        .send_transaction(signed_genesis, None)
        .expect("Genesis tx should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    println!(
        "Token created: ID=0x{}, genesis_tx=0x{}",
        hex::encode(&token_id[..8]),
        hex::encode(genesis_hash.as_bytes())
    );

    // Step 2: Mint tokens to recipient
    println!("Step 2: Minting 10000 tokens to recipient...");
    let mint_amount = 10000u64;

    // Fund the issuer with a separate cell for minting (to pay for CT token cell)
    let mint_funding_amount = 350_00000000u64; // 350 CKB for CT cell (223) + change + fees
    let mint_funding_cell = fund_account_with_stealth(env, &issuer, mint_funding_amount)
        .expect("Mint funding should succeed");

    println!(
        "Mint funding cell created: tx_hash=0x{}, capacity={} CKB",
        hex::encode(&mint_funding_cell.out_point[..32]),
        mint_funding_cell.capacity / 100_000_000
    );

    // Build ct-info cell input (from genesis output 0)
    let mut ct_info_out_point = Vec::with_capacity(36);
    ct_info_out_point.extend_from_slice(genesis_hash.as_bytes());
    ct_info_out_point.extend_from_slice(&0u32.to_le_bytes());

    let ct_info_cell_input = CtInfoCellInput {
        out_point: ct_info_out_point,
        lock_script_args: ct_info_lock_args.clone(),
        data: obscell_wallet::domain::ct_info::CtInfoData::new(0, 1_000_000, MINTABLE),
        capacity: 230_00000000, // ct-info cell capacity
    };

    let recipient_stealth_address = {
        let view_pub = recipient.view_public_key().serialize();
        let spend_pub = recipient.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let mint_params = MintParams {
        ct_info_cell: ct_info_cell_input,
        token_id,
        mint_amount,
        recipient_stealth_address,
        funding_cell: mint_funding_cell.clone(),
    };

    let built_mint =
        build_mint_transaction(&config, mint_params).expect("Building mint tx should succeed");

    println!(
        "Mint tx built: hash=0x{}, amount={}",
        hex::encode(built_mint.tx_hash.as_bytes()),
        mint_amount
    );

    // Sign the mint transaction
    let signed_mint = sign_mint_transaction(
        built_mint,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &ct_info_lock_args,
        &mint_funding_cell.lock_script_args,
    )
    .expect("Signing mint should succeed");

    // Submit mint transaction
    let mint_hash = client
        .send_transaction(signed_mint, None)
        .expect("Mint tx should succeed");

    println!("Mint tx sent: 0x{}", hex::encode(mint_hash.as_bytes()));

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Step 3: Verify recipient can scan and find the CT cell
    println!("Step 3: Recipient scanning for CT cells...");

    let scanner = Scanner::new(config.clone(), store);
    let ct_results = scanner
        .scan_ct_cells(&[recipient.clone()])
        .expect("CT scan should succeed");

    assert_eq!(ct_results.len(), 1, "Should have result for 1 account");
    let recipient_result = &ct_results[0];

    assert_eq!(
        recipient_result.cells.len(),
        1,
        "Recipient should have 1 CT cell"
    );

    let ct_cell = &recipient_result.cells[0];
    assert_eq!(
        ct_cell.amount, mint_amount,
        "CT cell amount should match minted amount"
    );

    println!(
        "Recipient found CT cell: amount={}, token_id=0x{}",
        ct_cell.amount,
        hex::encode(&ct_cell.token_id[..8])
    );

    // Verify balances
    assert_eq!(recipient_result.balances.len(), 1, "Should have 1 balance");
    let balance = &recipient_result.balances[0];
    assert_eq!(balance.total_amount, mint_amount, "Balance should match");

    println!("Mint test completed successfully!");
    println!("  - Token ID: 0x{}", hex::encode(&token_id));
    println!("  - Minted: {} tokens", mint_amount);
    println!("  - Recipient balance: {}", balance.total_amount);
}

/// Test CT token transfer between accounts.
#[test]
fn test_ct_transfer_between_accounts() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (alice_store, _alice_temp) = create_temp_store();
    let (bob_store, _bob_temp) = create_temp_store();

    // Create accounts
    let issuer = Account::new_random(0, "Issuer".to_string());
    let alice = Account::new_random(1, "Alice".to_string());
    let bob = Account::new_random(2, "Bob".to_string());

    println!("Issuer: {}", &issuer.stealth_address()[..32]);
    println!("Alice: {}", &alice.stealth_address()[..32]);
    println!("Bob: {}", &bob.stealth_address()[..32]);

    // Step 1: Create token and mint to Alice
    println!("Step 1: Creating token and minting to Alice...");

    let funding_cell =
        fund_account_with_stealth(env, &issuer, 350_00000000u64).expect("Funding should succeed");

    let issuer_stealth_address = {
        let view_pub = issuer.view_public_key().serialize();
        let spend_pub = issuer.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let genesis_params = GenesisParams {
        supply_cap: 1_000_000,
        flags: MINTABLE,
        issuer_stealth_address,
    };

    let genesis_tx = build_genesis_transaction(&config, genesis_params, funding_cell.clone())
        .expect("Genesis should succeed");

    let token_id = genesis_tx.token_id;
    let ct_info_lock_args = genesis_tx.ct_info_lock_args.clone();

    let signed_genesis = sign_genesis_transaction(
        genesis_tx,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &funding_cell.lock_script_args,
    )
    .expect("Signing genesis should succeed");

    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let genesis_hash = client
        .send_transaction(signed_genesis, None)
        .expect("Genesis should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Mint 1000 tokens to Alice
    let mint_amount = 1000u64;

    // Fund the issuer with a separate cell for minting
    let mint_funding_cell = fund_account_with_stealth(env, &issuer, 350_00000000u64)
        .expect("Mint funding should succeed");

    let mut ct_info_out_point = Vec::with_capacity(36);
    ct_info_out_point.extend_from_slice(genesis_hash.as_bytes());
    ct_info_out_point.extend_from_slice(&0u32.to_le_bytes());

    let alice_stealth_address = {
        let view_pub = alice.view_public_key().serialize();
        let spend_pub = alice.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let mint_params = MintParams {
        ct_info_cell: CtInfoCellInput {
            out_point: ct_info_out_point,
            lock_script_args: ct_info_lock_args.clone(),
            data: obscell_wallet::domain::ct_info::CtInfoData::new(0, 1_000_000, MINTABLE),
            capacity: 230_00000000,
        },
        token_id,
        mint_amount,
        recipient_stealth_address: alice_stealth_address,
        funding_cell: mint_funding_cell.clone(),
    };

    let built_mint = build_mint_transaction(&config, mint_params).expect("Mint should succeed");

    let signed_mint = sign_mint_transaction(
        built_mint,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &ct_info_lock_args,
        &mint_funding_cell.lock_script_args,
    )
    .expect("Signing mint should succeed");

    let mint_hash = client
        .send_transaction(signed_mint, None)
        .expect("Mint should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    println!(
        "Alice received {} tokens, mint_tx=0x{}",
        mint_amount,
        hex::encode(mint_hash.as_bytes())
    );

    // Step 2: Alice scans and finds her CT cell
    println!("Step 2: Alice scanning for CT cells...");

    let alice_scanner = Scanner::new(config.clone(), alice_store);
    let alice_results = alice_scanner
        .scan_ct_cells(&[alice.clone()])
        .expect("Alice scan should succeed");

    assert_eq!(
        alice_results[0].cells.len(),
        1,
        "Alice should have 1 CT cell"
    );
    let alice_ct_cell = alice_results[0].cells[0].clone();

    println!(
        "Alice found CT cell: amount={}, out_point=0x{}",
        alice_ct_cell.amount,
        hex::encode(&alice_ct_cell.out_point[..8])
    );

    // Step 3: Alice transfers 300 tokens to Bob
    println!("Step 3: Alice transferring 300 tokens to Bob...");
    let transfer_amount = 300u64;

    // Fund Alice with additional CKB for the transfer (1 input -> 2 outputs needs extra capacity)
    let transfer_funding_cell = fund_account_with_stealth(env, &alice, 350_00000000u64)
        .expect("Transfer funding should succeed");

    use obscell_wallet::domain::ct_tx_builder::CtTxBuilder;

    let bob_stealth_address = {
        let view_pub = bob.view_public_key().serialize();
        let spend_pub = bob.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let built_transfer = CtTxBuilder::new(config.clone(), alice_ct_cell.type_script_args.clone())
        .add_input(alice_ct_cell.clone())
        .add_output(bob_stealth_address, transfer_amount)
        .funding_cell(transfer_funding_cell.clone())
        .build(&alice)
        .expect("Building transfer should succeed");

    println!(
        "Transfer tx built: hash=0x{}, outputs={}",
        hex::encode(built_transfer.tx_hash.as_bytes()),
        built_transfer.tx.outputs.len()
    );

    // Sign the transfer (including funding cell)
    let signed_transfer = CtTxBuilder::sign(
        built_transfer,
        &alice,
        &alice.spend_secret_key_for_test(),
        &[alice_ct_cell.clone()],
        Some(&transfer_funding_cell.lock_script_args),
    )
    .expect("Signing transfer should succeed");

    // Submit the transfer
    let transfer_hash = client
        .send_transaction(signed_transfer, None)
        .expect("Transfer should succeed");

    println!(
        "Transfer tx sent: 0x{}",
        hex::encode(transfer_hash.as_bytes())
    );

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Step 4: Verify Bob received 300 tokens
    println!("Step 4: Bob scanning for CT cells...");

    let bob_scanner = Scanner::new(config.clone(), bob_store);
    let bob_results = bob_scanner
        .scan_ct_cells(&[bob.clone()])
        .expect("Bob scan should succeed");

    assert_eq!(bob_results[0].cells.len(), 1, "Bob should have 1 CT cell");
    let bob_ct_cell = &bob_results[0].cells[0];

    assert_eq!(
        bob_ct_cell.amount, transfer_amount,
        "Bob should have {} tokens",
        transfer_amount
    );

    println!(
        "Bob received {} tokens, token_id=0x{}",
        bob_ct_cell.amount,
        hex::encode(&bob_ct_cell.token_id[..8])
    );

    // Step 5: Verify Alice has change (700 tokens)
    println!("Step 5: Alice verifying change...");

    // Re-scan Alice with fresh scanner
    let (alice_store2, _temp2) = create_temp_store();
    let alice_scanner2 = Scanner::new(config.clone(), alice_store2);
    let alice_results2 = alice_scanner2
        .scan_ct_cells(&[alice.clone()])
        .expect("Alice rescan should succeed");

    // Alice should have 1 CT cell with change
    assert!(
        !alice_results2[0].cells.is_empty(),
        "Alice should have change cell"
    );

    let alice_total: u64 = alice_results2[0].cells.iter().map(|c| c.amount).sum();
    let expected_change = mint_amount - transfer_amount;

    assert_eq!(
        alice_total, expected_change,
        "Alice should have {} tokens remaining",
        expected_change
    );

    println!("Alice has {} tokens remaining (change)", alice_total);

    println!("\nCT Transfer test completed successfully!");
    println!("  - Token ID: 0x{}", hex::encode(&token_id));
    println!("  - Alice initial: {} tokens", mint_amount);
    println!("  - Transferred to Bob: {} tokens", transfer_amount);
    println!("  - Alice final: {} tokens", alice_total);
    println!("  - Bob final: {} tokens", bob_ct_cell.amount);
}

// ============================================================================
// Phase 2: Scanner and Persistence Tests
// ============================================================================

/// Test that scanner correctly finds CT cells for multiple accounts.
#[test]
fn test_scanner_finds_ct_cells_multi_account() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create issuer and two recipients
    let issuer = Account::new_random(0, "Issuer".to_string());
    let alice = Account::new_random(1, "Alice".to_string());
    let bob = Account::new_random(2, "Bob".to_string());

    println!("Setting up multi-account CT scan test...");

    // Create token
    let funding_cell =
        fund_account_with_stealth(env, &issuer, 350_00000000u64).expect("Funding should succeed");

    let issuer_stealth_address = {
        let view_pub = issuer.view_public_key().serialize();
        let spend_pub = issuer.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let genesis_tx = build_genesis_transaction(
        &config,
        GenesisParams {
            supply_cap: 1_000_000,
            flags: MINTABLE,
            issuer_stealth_address,
        },
        funding_cell.clone(),
    )
    .expect("Genesis should succeed");

    let token_id = genesis_tx.token_id;
    let ct_info_lock_args = genesis_tx.ct_info_lock_args.clone();

    let signed_genesis = sign_genesis_transaction(
        genesis_tx,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &funding_cell.lock_script_args,
    )
    .expect("Signing should succeed");

    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let genesis_hash = client
        .send_transaction(signed_genesis, None)
        .expect("Genesis should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Mint 500 tokens to Alice
    println!("Minting 500 tokens to Alice...");
    let alice_amount = 500u64;

    // Fund the issuer for first mint
    let mint1_funding = fund_account_with_stealth(env, &issuer, 350_00000000u64)
        .expect("Mint1 funding should succeed");

    let mut ct_info_out_point = Vec::with_capacity(36);
    ct_info_out_point.extend_from_slice(genesis_hash.as_bytes());
    ct_info_out_point.extend_from_slice(&0u32.to_le_bytes());

    let alice_stealth = {
        let view_pub = alice.view_public_key().serialize();
        let spend_pub = alice.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let mint1 = build_mint_transaction(
        &config,
        MintParams {
            ct_info_cell: CtInfoCellInput {
                out_point: ct_info_out_point,
                lock_script_args: ct_info_lock_args.clone(),
                data: obscell_wallet::domain::ct_info::CtInfoData::new(0, 1_000_000, MINTABLE),
                capacity: 230_00000000,
            },
            token_id,
            mint_amount: alice_amount,
            recipient_stealth_address: alice_stealth,
            funding_cell: mint1_funding.clone(),
        },
    )
    .expect("Mint should succeed");

    let signed_mint1 = sign_mint_transaction(
        mint1,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &ct_info_lock_args,
        &mint1_funding.lock_script_args,
    )
    .expect("Signing should succeed");

    let mint1_hash = client
        .send_transaction(signed_mint1, None)
        .expect("Mint should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Mint 300 tokens to Bob (using updated ct-info cell)
    println!("Minting 300 tokens to Bob...");
    let bob_amount = 300u64;

    // Fund the issuer for second mint
    let mint2_funding = fund_account_with_stealth(env, &issuer, 350_00000000u64)
        .expect("Mint2 funding should succeed");

    let mut ct_info_out_point2 = Vec::with_capacity(36);
    ct_info_out_point2.extend_from_slice(mint1_hash.as_bytes());
    ct_info_out_point2.extend_from_slice(&0u32.to_le_bytes());

    let bob_stealth = {
        let view_pub = bob.view_public_key().serialize();
        let spend_pub = bob.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let mint2 = build_mint_transaction(
        &config,
        MintParams {
            ct_info_cell: CtInfoCellInput {
                out_point: ct_info_out_point2,
                lock_script_args: ct_info_lock_args.clone(),
                data: obscell_wallet::domain::ct_info::CtInfoData::new(
                    alice_amount as u128,
                    1_000_000,
                    MINTABLE,
                ),
                capacity: 230_00000000,
            },
            token_id,
            mint_amount: bob_amount,
            recipient_stealth_address: bob_stealth,
            funding_cell: mint2_funding.clone(),
        },
    )
    .expect("Mint should succeed");

    let signed_mint2 = sign_mint_transaction(
        mint2,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &ct_info_lock_args,
        &mint2_funding.lock_script_args,
    )
    .expect("Signing should succeed");

    client
        .send_transaction(signed_mint2, None)
        .expect("Mint should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Scan for both accounts simultaneously
    println!("Scanning for CT cells (Alice and Bob)...");
    let scanner = Scanner::new(config, store);
    let results = scanner
        .scan_ct_cells(&[alice.clone(), bob.clone()])
        .expect("Scan should succeed");

    assert_eq!(results.len(), 2, "Should have results for 2 accounts");

    // Verify Alice's results
    let alice_result = results.iter().find(|r| r.account_id == 1).unwrap();
    assert_eq!(alice_result.cells.len(), 1, "Alice should have 1 CT cell");
    assert_eq!(
        alice_result.cells[0].amount, alice_amount,
        "Alice should have {} tokens",
        alice_amount
    );

    // Verify Bob's results
    let bob_result = results.iter().find(|r| r.account_id == 2).unwrap();
    assert_eq!(bob_result.cells.len(), 1, "Bob should have 1 CT cell");
    assert_eq!(
        bob_result.cells[0].amount, bob_amount,
        "Bob should have {} tokens",
        bob_amount
    );

    println!("Multi-account CT scan test passed!");
    println!(
        "  - Alice: {} tokens",
        alice_result.balances[0].total_amount
    );
    println!("  - Bob: {} tokens", bob_result.balances[0].total_amount);
}

/// Test that scanner correctly finds ct-info cells owned by issuer.
#[test]
fn test_scanner_finds_ct_info_cells() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create issuer
    let issuer = Account::new_random(0, "Issuer".to_string());

    println!("Setting up ct-info cell scan test...");

    // Create token (this creates a ct-info cell owned by issuer)
    let funding_cell =
        fund_account_with_stealth(env, &issuer, 350_00000000u64).expect("Funding should succeed");

    let issuer_stealth_address = {
        let view_pub = issuer.view_public_key().serialize();
        let spend_pub = issuer.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let genesis_tx = build_genesis_transaction(
        &config,
        GenesisParams {
            supply_cap: 5_000_000,
            flags: MINTABLE,
            issuer_stealth_address,
        },
        funding_cell.clone(),
    )
    .expect("Genesis should succeed");

    let token_id = genesis_tx.token_id;

    let signed_genesis = sign_genesis_transaction(
        genesis_tx,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &funding_cell.lock_script_args,
    )
    .expect("Signing should succeed");

    let client = CkbRpcClient::new(DevNet::RPC_URL);
    client
        .send_transaction(signed_genesis, None)
        .expect("Genesis should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Scan for ct-info cells
    println!("Scanning for ct-info cells...");
    let scanner = Scanner::new(config, store);
    let results = scanner
        .scan_ct_info_cells(&[issuer.clone()])
        .expect("Scan should succeed");

    assert_eq!(results.len(), 1, "Should have result for 1 account");
    let issuer_result = &results[0];

    assert_eq!(
        issuer_result.cells.len(),
        1,
        "Issuer should have 1 ct-info cell"
    );

    let ct_info_cell = &issuer_result.cells[0];
    // genesis_tx.token_id is the Type ID, which should match ct_info_cell.type_id
    assert_eq!(ct_info_cell.type_id, token_id, "Type ID should match");
    assert_eq!(ct_info_cell.total_supply, 0, "Initial supply should be 0");
    assert_eq!(
        ct_info_cell.supply_cap, 5_000_000,
        "Supply cap should match"
    );
    assert_eq!(ct_info_cell.flags, MINTABLE, "Flags should be MINTABLE");

    println!("CT-info cell scan test passed!");
    println!("  - Token ID: 0x{}", hex::encode(&token_id[..8]));
    println!("  - Supply cap: {}", ct_info_cell.supply_cap);
    println!("  - Total supply: {}", ct_info_cell.total_supply);
}

/// Test that CT cells are correctly persisted to store across scans.
#[test]
fn test_ct_cells_persisted_to_store() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create issuer and recipient
    let issuer = Account::new_random(0, "Issuer".to_string());
    let alice = Account::new_random(1, "Alice".to_string());

    println!("Setting up CT cell persistence test...");

    // Create and mint token
    let funding_cell =
        fund_account_with_stealth(env, &issuer, 350_00000000u64).expect("Funding should succeed");

    let issuer_stealth_address = {
        let view_pub = issuer.view_public_key().serialize();
        let spend_pub = issuer.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let genesis_tx = build_genesis_transaction(
        &config,
        GenesisParams {
            supply_cap: 1_000_000,
            flags: MINTABLE,
            issuer_stealth_address,
        },
        funding_cell.clone(),
    )
    .expect("Genesis should succeed");

    let token_id = genesis_tx.token_id;
    let ct_info_lock_args = genesis_tx.ct_info_lock_args.clone();

    let signed_genesis = sign_genesis_transaction(
        genesis_tx,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &funding_cell.lock_script_args,
    )
    .expect("Signing should succeed");

    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let genesis_hash = client
        .send_transaction(signed_genesis, None)
        .expect("Genesis should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Mint to Alice
    let mint_amount = 1000u64;

    // Fund the issuer for minting
    let mint_funding = fund_account_with_stealth(env, &issuer, 350_00000000u64)
        .expect("Mint funding should succeed");

    let mut ct_info_out_point = Vec::with_capacity(36);
    ct_info_out_point.extend_from_slice(genesis_hash.as_bytes());
    ct_info_out_point.extend_from_slice(&0u32.to_le_bytes());

    let alice_stealth = {
        let view_pub = alice.view_public_key().serialize();
        let spend_pub = alice.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let mint_tx = build_mint_transaction(
        &config,
        MintParams {
            ct_info_cell: CtInfoCellInput {
                out_point: ct_info_out_point,
                lock_script_args: ct_info_lock_args.clone(),
                data: obscell_wallet::domain::ct_info::CtInfoData::new(0, 1_000_000, MINTABLE),
                capacity: 230_00000000,
            },
            token_id,
            mint_amount,
            recipient_stealth_address: alice_stealth,
            funding_cell: mint_funding.clone(),
        },
    )
    .expect("Mint should succeed");

    let signed_mint = sign_mint_transaction(
        mint_tx,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &ct_info_lock_args,
        &mint_funding.lock_script_args,
    )
    .expect("Signing should succeed");

    client
        .send_transaction(signed_mint, None)
        .expect("Mint should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // First scan
    println!("First scan...");
    let scanner = Scanner::new(config.clone(), store.clone());
    let results1 = scanner
        .scan_ct_cells(&[alice.clone()])
        .expect("First scan should succeed");

    assert_eq!(results1[0].cells.len(), 1, "Should find 1 CT cell");
    assert_eq!(results1[0].new_cells.len(), 1, "All cells should be new");

    // Verify cells are persisted
    let stored_cells = store
        .get_ct_cells(alice.id)
        .expect("Should load from store");
    assert_eq!(stored_cells.len(), 1, "Store should have 1 CT cell");
    assert_eq!(
        stored_cells[0].amount, mint_amount,
        "Stored amount should match"
    );

    // Second scan - should not find new cells
    println!("Second scan (should find no new cells)...");
    let results2 = scanner
        .scan_ct_cells(&[alice.clone()])
        .expect("Second scan should succeed");

    assert_eq!(results2[0].cells.len(), 1, "Should still find 1 CT cell");
    assert_eq!(
        results2[0].new_cells.len(),
        0,
        "Should have no new cells on second scan"
    );

    println!("CT cell persistence test passed!");
    println!("  - Stored cells: {}", stored_cells.len());
    println!("  - First scan new cells: {}", results1[0].new_cells.len());
    println!("  - Second scan new cells: {}", results2[0].new_cells.len());
}

// ============================================================================
// Phase 3: Edge Cases and Advanced Tests
// ============================================================================

/// Test CT transfer with explicit change output verification.
#[test]
fn test_ct_transfer_with_change_verification() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (alice_store, _alice_temp) = create_temp_store();
    let (bob_store, _bob_temp) = create_temp_store();

    let issuer = Account::new_random(0, "Issuer".to_string());
    let alice = Account::new_random(1, "Alice".to_string());
    let bob = Account::new_random(2, "Bob".to_string());

    println!("Setting up CT transfer with change test...");

    // Create token and mint 1000 to Alice
    let funding_cell =
        fund_account_with_stealth(env, &issuer, 350_00000000u64).expect("Funding should succeed");

    let issuer_stealth = {
        let view_pub = issuer.view_public_key().serialize();
        let spend_pub = issuer.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let genesis_tx = build_genesis_transaction(
        &config,
        GenesisParams {
            supply_cap: 1_000_000,
            flags: MINTABLE,
            issuer_stealth_address: issuer_stealth,
        },
        funding_cell.clone(),
    )
    .expect("Genesis should succeed");

    let token_id = genesis_tx.token_id;
    let ct_info_lock_args = genesis_tx.ct_info_lock_args.clone();

    let signed_genesis = sign_genesis_transaction(
        genesis_tx,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &funding_cell.lock_script_args,
    )
    .expect("Signing should succeed");

    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let genesis_hash = client
        .send_transaction(signed_genesis, None)
        .expect("Genesis should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Mint 1000 to Alice
    let initial_amount = 1000u64;

    // Fund the issuer for minting
    let mint_funding = fund_account_with_stealth(env, &issuer, 350_00000000u64)
        .expect("Mint funding should succeed");

    let mut ct_info_out_point = Vec::with_capacity(36);
    ct_info_out_point.extend_from_slice(genesis_hash.as_bytes());
    ct_info_out_point.extend_from_slice(&0u32.to_le_bytes());

    let alice_stealth = {
        let view_pub = alice.view_public_key().serialize();
        let spend_pub = alice.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let mint_tx = build_mint_transaction(
        &config,
        MintParams {
            ct_info_cell: CtInfoCellInput {
                out_point: ct_info_out_point,
                lock_script_args: ct_info_lock_args.clone(),
                data: obscell_wallet::domain::ct_info::CtInfoData::new(0, 1_000_000, MINTABLE),
                capacity: 230_00000000,
            },
            token_id,
            mint_amount: initial_amount,
            recipient_stealth_address: alice_stealth,
            funding_cell: mint_funding.clone(),
        },
    )
    .expect("Mint should succeed");

    let signed_mint = sign_mint_transaction(
        mint_tx,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &ct_info_lock_args,
        &mint_funding.lock_script_args,
    )
    .expect("Signing should succeed");

    client
        .send_transaction(signed_mint, None)
        .expect("Mint should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Alice scans
    let alice_scanner = Scanner::new(config.clone(), alice_store);
    let alice_results = alice_scanner
        .scan_ct_cells(&[alice.clone()])
        .expect("Alice scan should succeed");

    let alice_ct_cell = alice_results[0].cells[0].clone();

    // Alice transfers 250 to Bob (should create change of 750)
    let transfer_amount = 250u64;
    let expected_change = initial_amount - transfer_amount;

    // Fund Alice with additional CKB for the transfer (1 input -> 2 outputs needs extra capacity)
    let transfer_funding = fund_account_with_stealth(env, &alice, 350_00000000u64)
        .expect("Transfer funding should succeed");

    println!(
        "Alice transferring {} tokens to Bob (expecting {} change)...",
        transfer_amount, expected_change
    );

    use obscell_wallet::domain::ct_tx_builder::CtTxBuilder;

    let bob_stealth = {
        let view_pub = bob.view_public_key().serialize();
        let spend_pub = bob.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let transfer_tx = CtTxBuilder::new(config.clone(), alice_ct_cell.type_script_args.clone())
        .add_input(alice_ct_cell.clone())
        .add_output(bob_stealth, transfer_amount)
        .funding_cell(transfer_funding.clone())
        .build(&alice)
        .expect("Transfer should succeed");

    // Verify the transaction has 2 CT outputs + 1 CKB change output
    assert!(
        transfer_tx.tx.outputs.len() >= 2,
        "Transfer should have at least 2 outputs (recipient + CT change)"
    );

    let signed_transfer = CtTxBuilder::sign(
        transfer_tx,
        &alice,
        &alice.spend_secret_key_for_test(),
        &[alice_ct_cell.clone()],
        Some(&transfer_funding.lock_script_args),
    )
    .expect("Signing should succeed");

    client
        .send_transaction(signed_transfer, None)
        .expect("Transfer should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Verify Bob received correct amount
    let bob_scanner = Scanner::new(config.clone(), bob_store);
    let bob_results = bob_scanner
        .scan_ct_cells(&[bob.clone()])
        .expect("Bob scan should succeed");

    assert_eq!(bob_results[0].cells.len(), 1);
    assert_eq!(bob_results[0].cells[0].amount, transfer_amount);

    // Verify Alice has correct change
    let (alice_store2, _temp2) = create_temp_store();
    let alice_scanner2 = Scanner::new(config.clone(), alice_store2);
    let alice_results2 = alice_scanner2
        .scan_ct_cells(&[alice.clone()])
        .expect("Alice rescan should succeed");

    assert_eq!(alice_results2[0].cells.len(), 1, "Alice should have 1 cell");
    assert_eq!(
        alice_results2[0].cells[0].amount, expected_change,
        "Alice change should be {} tokens",
        expected_change
    );

    println!("CT transfer with change test passed!");
    println!("  - Initial: {} tokens", initial_amount);
    println!("  - Transferred: {} tokens", transfer_amount);
    println!(
        "  - Bob received: {} tokens",
        bob_results[0].cells[0].amount
    );
    println!(
        "  - Alice change: {} tokens",
        alice_results2[0].cells[0].amount
    );
}

/// Test that minting beyond supply cap fails.
#[test]
fn test_ct_mint_exceeds_supply_cap_fails() {
    let env = TestEnv::get();
    let config = create_test_config(env);

    let issuer = Account::new_random(0, "Issuer".to_string());
    let recipient = Account::new_random(1, "Recipient".to_string());

    println!("Setting up supply cap test...");

    // Create token with small supply cap
    let funding_cell =
        fund_account_with_stealth(env, &issuer, 350_00000000u64).expect("Funding should succeed");

    let issuer_stealth = {
        let view_pub = issuer.view_public_key().serialize();
        let spend_pub = issuer.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let supply_cap = 100u128; // Very small cap

    let genesis_tx = build_genesis_transaction(
        &config,
        GenesisParams {
            supply_cap,
            flags: MINTABLE,
            issuer_stealth_address: issuer_stealth,
        },
        funding_cell.clone(),
    )
    .expect("Genesis should succeed");

    let token_id = genesis_tx.token_id;
    let ct_info_lock_args = genesis_tx.ct_info_lock_args.clone();

    let signed_genesis = sign_genesis_transaction(
        genesis_tx,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &funding_cell.lock_script_args,
    )
    .expect("Signing should succeed");

    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let genesis_hash = client
        .send_transaction(signed_genesis, None)
        .expect("Genesis should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Try to mint more than supply cap
    // Fund the issuer for the mint attempt (even though it should fail)
    let mint_funding = fund_account_with_stealth(env, &issuer, 350_00000000u64)
        .expect("Mint funding should succeed");

    let mut ct_info_out_point = Vec::with_capacity(36);
    ct_info_out_point.extend_from_slice(genesis_hash.as_bytes());
    ct_info_out_point.extend_from_slice(&0u32.to_le_bytes());

    let recipient_stealth = {
        let view_pub = recipient.view_public_key().serialize();
        let spend_pub = recipient.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let exceed_amount = 200u64; // More than cap of 100

    println!(
        "Attempting to mint {} tokens (cap is {})...",
        exceed_amount, supply_cap
    );

    let result = build_mint_transaction(
        &config,
        MintParams {
            ct_info_cell: CtInfoCellInput {
                out_point: ct_info_out_point,
                lock_script_args: ct_info_lock_args,
                data: obscell_wallet::domain::ct_info::CtInfoData::new(0, supply_cap, MINTABLE),
                capacity: 230_00000000,
            },
            token_id,
            mint_amount: exceed_amount,
            recipient_stealth_address: recipient_stealth,
            funding_cell: mint_funding,
        },
    );

    assert!(
        result.is_err(),
        "Minting beyond supply cap should fail at build time"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("exceed") || err_msg.contains("cap"),
        "Error should mention exceeding cap: {}",
        err_msg
    );

    println!("Supply cap enforcement test passed!");
    println!("  - Supply cap: {}", supply_cap);
    println!("  - Attempted mint: {}", exceed_amount);
    println!("  - Result: Correctly rejected");
}

/// Test CT balance aggregation with multiple cells of the same token.
#[test]
fn test_ct_balance_aggregation_multiple_cells() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    let issuer = Account::new_random(0, "Issuer".to_string());
    let alice = Account::new_random(1, "Alice".to_string());

    println!("Setting up balance aggregation test...");

    // Create token
    let funding_cell =
        fund_account_with_stealth(env, &issuer, 500_00000000u64).expect("Funding should succeed");

    let issuer_stealth = {
        let view_pub = issuer.view_public_key().serialize();
        let spend_pub = issuer.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let genesis_tx = build_genesis_transaction(
        &config,
        GenesisParams {
            supply_cap: 10_000,
            flags: MINTABLE,
            issuer_stealth_address: issuer_stealth,
        },
        funding_cell.clone(),
    )
    .expect("Genesis should succeed");

    let token_id = genesis_tx.token_id;
    let ct_info_lock_args = genesis_tx.ct_info_lock_args.clone();

    let signed_genesis = sign_genesis_transaction(
        genesis_tx,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &funding_cell.lock_script_args,
    )
    .expect("Signing should succeed");

    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let genesis_hash = client
        .send_transaction(signed_genesis, None)
        .expect("Genesis should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Mint multiple times to Alice
    let amounts = [100u64, 200u64, 300u64];
    let mut current_supply = 0u128;
    let mut last_tx_hash = genesis_hash;

    let alice_stealth = {
        let view_pub = alice.view_public_key().serialize();
        let spend_pub = alice.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    for (i, &amount) in amounts.iter().enumerate() {
        println!("Mint #{}: {} tokens to Alice", i + 1, amount);

        // Fund the issuer for this mint
        let mint_funding = fund_account_with_stealth(env, &issuer, 350_00000000u64)
            .expect("Mint funding should succeed");

        let mut ct_info_out_point = Vec::with_capacity(36);
        ct_info_out_point.extend_from_slice(last_tx_hash.as_bytes());
        ct_info_out_point.extend_from_slice(&0u32.to_le_bytes());

        let mint_tx = build_mint_transaction(
            &config,
            MintParams {
                ct_info_cell: CtInfoCellInput {
                    out_point: ct_info_out_point,
                    lock_script_args: ct_info_lock_args.clone(),
                    data: obscell_wallet::domain::ct_info::CtInfoData::new(
                        current_supply,
                        10_000,
                        MINTABLE,
                    ),
                    capacity: 230_00000000,
                },
                token_id,
                mint_amount: amount,
                recipient_stealth_address: alice_stealth.clone(),
                funding_cell: mint_funding.clone(),
            },
        )
        .expect("Mint should succeed");

        let signed_mint = sign_mint_transaction(
            mint_tx,
            &issuer,
            &issuer.spend_secret_key_for_test(),
            &ct_info_lock_args,
            &mint_funding.lock_script_args,
        )
        .expect("Signing should succeed");

        last_tx_hash = client
            .send_transaction(signed_mint, None)
            .expect("Mint should succeed");

        current_supply += amount as u128;

        env.generate_blocks(10).expect("Should generate blocks");
        env.wait_for_indexer_sync().expect("Should sync");
    }

    // Scan and verify aggregated balance
    println!("Scanning and verifying aggregated balance...");
    let scanner = Scanner::new(config, store);
    let results = scanner
        .scan_ct_cells(&[alice.clone()])
        .expect("Scan should succeed");

    let alice_result = &results[0];

    assert_eq!(
        alice_result.cells.len(),
        amounts.len(),
        "Alice should have {} CT cells",
        amounts.len()
    );

    // Verify individual cells
    let mut found_amounts: Vec<u64> = alice_result.cells.iter().map(|c| c.amount).collect();
    found_amounts.sort();
    let mut expected_amounts = amounts.to_vec();
    expected_amounts.sort();
    assert_eq!(
        found_amounts, expected_amounts,
        "Cell amounts should match minted amounts"
    );

    // Verify aggregated balance
    assert_eq!(alice_result.balances.len(), 1, "Should have 1 token type");
    let balance = &alice_result.balances[0];
    let expected_total: u64 = amounts.iter().sum();
    assert_eq!(
        balance.total_amount, expected_total,
        "Aggregated balance should be {}",
        expected_total
    );
    assert_eq!(
        balance.cell_count,
        amounts.len(),
        "Cell count should be {}",
        amounts.len()
    );

    println!("Balance aggregation test passed!");
    println!("  - Minted amounts: {:?}", amounts);
    println!("  - Cells found: {}", alice_result.cells.len());
    println!("  - Total balance: {}", balance.total_amount);
    println!("  - Cell count: {}", balance.cell_count);
}

/// Test CT token genesis and mint with UNLIMITED supply (supply_cap = 0).
/// This specifically tests the scenario where user creates a token without a supply cap.
#[test]
fn test_ct_mint_unlimited_supply() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (_store, _temp_dir) = create_temp_store();

    // Create issuer and recipient accounts
    let issuer = Account::new_random(0, "Issuer".to_string());
    let recipient = Account::new_random(1, "Recipient".to_string());

    println!("=== Testing UNLIMITED supply CT token mint ===");
    println!("Issuer: {}", &issuer.stealth_address()[..32]);
    println!("Recipient: {}", &recipient.stealth_address()[..32]);

    // Step 1: Create the CT token with UNLIMITED supply (supply_cap = 0)
    println!("\nStep 1: Creating CT token with UNLIMITED supply (supply_cap = 0)...");
    let funding_amount = 350_00000000u64;
    let funding_cell =
        fund_account_with_stealth(env, &issuer, funding_amount).expect("Funding should succeed");

    let issuer_stealth_address = {
        let view_pub = issuer.view_public_key().serialize();
        let spend_pub = issuer.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let genesis_params = GenesisParams {
        supply_cap: 0, // UNLIMITED - this is the key difference!
        flags: MINTABLE,
        issuer_stealth_address: issuer_stealth_address.clone(),
    };

    let genesis_tx = build_genesis_transaction(&config, genesis_params, funding_cell.clone())
        .expect("Building genesis tx should succeed");

    let token_id = genesis_tx.token_id;
    let ct_info_lock_args = genesis_tx.ct_info_lock_args.clone();

    println!(
        "Genesis tx built: token_id=0x{}, supply_cap=UNLIMITED",
        hex::encode(&token_id[..8])
    );

    let signed_genesis = sign_genesis_transaction(
        genesis_tx,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &funding_cell.lock_script_args,
    )
    .expect("Signing genesis should succeed");

    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let genesis_hash = client
        .send_transaction(signed_genesis, None)
        .expect("Genesis tx should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    println!(
        "Token created: genesis_tx=0x{}",
        hex::encode(genesis_hash.as_bytes())
    );

    // Verify the ct-info cell has supply_cap = 0
    let ct_info_out_point = ckb_jsonrpc_types::OutPoint {
        tx_hash: genesis_hash.clone(),
        index: ckb_jsonrpc_types::Uint32::from(0u32),
    };
    let cell_with_status = client
        .get_live_cell(ct_info_out_point, true)
        .expect("Should get cell")
        .cell
        .expect("Cell should exist");
    let cell_data = cell_with_status.data.unwrap();
    let data_bytes = cell_data.content.as_bytes();
    let supply_cap = u128::from_le_bytes(data_bytes[16..32].try_into().unwrap());
    assert_eq!(supply_cap, 0, "Supply cap should be 0 (unlimited)");
    println!("Verified: ct-info cell supply_cap = 0 (UNLIMITED)");

    // Step 2: Mint tokens to recipient
    println!("\nStep 2: Minting 10000 tokens to recipient...");
    let mint_amount = 10000u64;

    // Fund the issuer with a separate cell for minting
    let mint_funding_amount = 350_00000000u64;
    let mint_funding_cell = fund_account_with_stealth(env, &issuer, mint_funding_amount)
        .expect("Mint funding should succeed");

    println!(
        "Mint funding cell created: capacity={} CKB",
        mint_funding_cell.capacity / 100_000_000
    );

    // Build ct-info cell input (from genesis output 0)
    let mut ct_info_out_point_bytes = Vec::with_capacity(36);
    ct_info_out_point_bytes.extend_from_slice(genesis_hash.as_bytes());
    ct_info_out_point_bytes.extend_from_slice(&0u32.to_le_bytes());

    let ct_info_cell_input = CtInfoCellInput {
        out_point: ct_info_out_point_bytes,
        lock_script_args: ct_info_lock_args.clone(),
        data: obscell_wallet::domain::ct_info::CtInfoData::new(
            0,        // total_supply = 0 (first mint)
            0,        // supply_cap = 0 (UNLIMITED)
            MINTABLE, // flags
        ),
        capacity: 230_00000000,
    };

    let recipient_stealth_address = {
        let view_pub = recipient.view_public_key().serialize();
        let spend_pub = recipient.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    println!("Building mint transaction...");
    println!("  - ct_info total_supply: 0");
    println!("  - ct_info supply_cap: 0 (UNLIMITED)");
    println!("  - mint_amount: {}", mint_amount);

    let mint_params = MintParams {
        ct_info_cell: ct_info_cell_input,
        token_id,
        mint_amount,
        recipient_stealth_address,
        funding_cell: mint_funding_cell.clone(),
    };

    let built_mint =
        build_mint_transaction(&config, mint_params).expect("Building mint tx should succeed");

    println!(
        "Mint tx built: hash=0x{}, range_proof_size={} bytes",
        hex::encode(built_mint.tx_hash.as_bytes()),
        built_mint.range_proof_bytes.len()
    );
    println!(
        "  - mint_commitment: 0x{}",
        hex::encode(&built_mint.mint_commitment)
    );

    // Sign the mint transaction
    println!("\nStep 3: Signing mint transaction...");
    let signed_mint = sign_mint_transaction(
        built_mint,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &ct_info_lock_args,
        &mint_funding_cell.lock_script_args,
    )
    .expect("Signing mint tx should succeed");

    // Submit the mint transaction
    println!("Step 4: Submitting mint transaction...");
    let mint_result = client.send_transaction(signed_mint, None);

    match mint_result {
        Ok(tx_hash) => {
            println!(
                "SUCCESS! Mint tx sent: 0x{}",
                hex::encode(tx_hash.as_bytes())
            );

            env.generate_blocks(10).expect("Should generate blocks");
            env.wait_for_indexer_sync().expect("Should sync");

            // Verify the minted CT token cell
            let ct_token_out_point = ckb_jsonrpc_types::OutPoint {
                tx_hash: tx_hash.clone(),
                index: ckb_jsonrpc_types::Uint32::from(1u32), // CT token is output 1
            };
            let ct_token_cell = client
                .get_live_cell(ct_token_out_point, true)
                .expect("Should get cell")
                .cell
                .expect("CT token cell should exist");

            let ct_token_data = ct_token_cell.data.unwrap();
            assert_eq!(
                ct_token_data.content.as_bytes().len(),
                64,
                "CT token data should be 64 bytes"
            );

            println!("CT token cell verified: 64 bytes of data (commitment + encrypted amount)");
            println!("\n=== UNLIMITED supply mint test PASSED! ===");
        }
        Err(e) => {
            panic!(
                "FAILED! Mint transaction rejected with error:\n{:#?}\n\
                This is the bug we're trying to reproduce - InvalidRangeProof (error 9)",
                e
            );
        }
    }
}

// ============================================================================
// Regression Tests for Bug Fixes
// ============================================================================

/// Test that consecutive mints work correctly.
///
/// This is a regression test for the bug where spent funding cells were not
/// removed from the store after a successful mint, causing subsequent operations
/// to fail with "Unknown OutPoint" errors.
///
/// The test verifies:
/// 1. First mint succeeds and creates a CT cell
/// 2. Second mint succeeds using a different funding cell
/// 3. Both minted CT cells are scannable
#[test]
fn test_consecutive_mints_use_different_funding_cells() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    println!("\n=== Testing consecutive mints with funding cell cleanup ===\n");

    // Create issuer account
    let issuer = Account::new_random(0, "Issuer".to_string());
    println!("Issuer created: {}", &issuer.stealth_address()[..32]);

    // Fund issuer for genesis
    let genesis_funding = fund_account_with_stealth(env, &issuer, 350_00000000u64)
        .expect("Genesis funding should succeed");

    // Create issuer stealth address for ct-info ownership
    let issuer_stealth_address = {
        let view_pub = issuer.view_public_key().serialize();
        let spend_pub = issuer.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    // Genesis: Create token with supply cap 1,000,000
    let genesis_params = GenesisParams {
        issuer_stealth_address: issuer_stealth_address.clone(),
        supply_cap: 1_000_000,
        flags: MINTABLE,
    };

    let built_genesis = build_genesis_transaction(&config, genesis_params, genesis_funding.clone())
        .expect("Genesis build should succeed");
    let token_id = built_genesis.token_id;
    let ct_info_lock_args = built_genesis.ct_info_lock_args.clone();

    let signed_genesis = sign_genesis_transaction(
        built_genesis,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &genesis_funding.lock_script_args,
    )
    .expect("Genesis signing should succeed");

    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let genesis_hash = client
        .send_transaction(signed_genesis, None)
        .expect("Genesis tx should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    println!(
        "Token created: ID=0x{}, genesis_tx=0x{}",
        hex::encode(&token_id[..8]),
        hex::encode(genesis_hash.as_bytes())
    );

    // Fund issuer with TWO separate cells for two mints
    println!("\nFunding issuer with two separate cells for consecutive mints...");
    let mint_funding_1 = fund_account_with_stealth(env, &issuer, 300_00000000u64)
        .expect("First mint funding should succeed");
    let mint_funding_2 = fund_account_with_stealth(env, &issuer, 300_00000000u64)
        .expect("Second mint funding should succeed");

    // Verify the two funding cells have different out_points
    assert_ne!(
        mint_funding_1.out_point, mint_funding_2.out_point,
        "Funding cells should have different out_points"
    );
    println!(
        "Funding cell 1: 0x{}",
        hex::encode(&mint_funding_1.out_point[..8])
    );
    println!(
        "Funding cell 2: 0x{}",
        hex::encode(&mint_funding_2.out_point[..8])
    );

    // Build ct-info out_point for mints
    let mut ct_info_out_point = Vec::with_capacity(36);
    ct_info_out_point.extend_from_slice(genesis_hash.as_bytes());
    ct_info_out_point.extend_from_slice(&0u32.to_le_bytes());

    // First mint: 1000 tokens
    println!("\nMint 1: Minting 1000 tokens...");
    let mint_amount_1 = 1000u64;

    let mint_params_1 = MintParams {
        ct_info_cell: CtInfoCellInput {
            out_point: ct_info_out_point.clone(),
            lock_script_args: ct_info_lock_args.clone(),
            data: obscell_wallet::domain::ct_info::CtInfoData::new(0, 1_000_000, MINTABLE),
            capacity: 230_00000000,
        },
        token_id,
        mint_amount: mint_amount_1,
        recipient_stealth_address: issuer_stealth_address.clone(),
        funding_cell: mint_funding_1.clone(),
    };

    let built_mint_1 =
        build_mint_transaction(&config, mint_params_1).expect("First mint build should succeed");
    let mint_1_hash = built_mint_1.tx_hash.clone();

    let signed_mint_1 = sign_mint_transaction(
        built_mint_1,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &ct_info_lock_args,
        &mint_funding_1.lock_script_args,
    )
    .expect("First mint signing should succeed");

    let mint_1_result = client.send_transaction(signed_mint_1, None);
    assert!(
        mint_1_result.is_ok(),
        "First mint should succeed: {:?}",
        mint_1_result.err()
    );

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    println!(
        "Mint 1 succeeded: {} tokens, tx=0x{}",
        mint_amount_1,
        hex::encode(mint_1_hash.as_bytes())
    );

    // Update ct-info out_point for second mint (points to output of first mint)
    let mut ct_info_out_point_2 = Vec::with_capacity(36);
    ct_info_out_point_2.extend_from_slice(mint_1_hash.as_bytes());
    ct_info_out_point_2.extend_from_slice(&0u32.to_le_bytes());

    // Second mint: 2000 tokens (using different funding cell)
    println!("\nMint 2: Minting 2000 tokens with different funding cell...");
    let mint_amount_2 = 2000u64;

    let mint_params_2 = MintParams {
        ct_info_cell: CtInfoCellInput {
            out_point: ct_info_out_point_2,
            lock_script_args: ct_info_lock_args.clone(),
            data: obscell_wallet::domain::ct_info::CtInfoData::new(
                mint_amount_1 as u128,
                1_000_000,
                MINTABLE,
            ),
            capacity: 230_00000000,
        },
        token_id,
        mint_amount: mint_amount_2,
        recipient_stealth_address: issuer_stealth_address.clone(),
        funding_cell: mint_funding_2.clone(), // Different funding cell!
    };

    let built_mint_2 =
        build_mint_transaction(&config, mint_params_2).expect("Second mint build should succeed");

    let signed_mint_2 = sign_mint_transaction(
        built_mint_2,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &ct_info_lock_args,
        &mint_funding_2.lock_script_args,
    )
    .expect("Second mint signing should succeed");

    // This is the critical test: second mint should NOT fail with "Unknown OutPoint"
    let mint_2_result = client.send_transaction(signed_mint_2, None);
    assert!(
        mint_2_result.is_ok(),
        "Second mint should succeed (not fail with Unknown OutPoint): {:?}",
        mint_2_result.err()
    );

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    println!(
        "Mint 2 succeeded: {} tokens, tx=0x{}",
        mint_amount_2,
        hex::encode(mint_2_result.unwrap().as_bytes())
    );

    // Verify both CT cells are scannable
    println!("\nVerifying minted CT cells...");
    let scanner = Scanner::new(config.clone(), store);
    let scan_results = scanner
        .scan_ct_cells(std::slice::from_ref(&issuer))
        .expect("Scan should succeed");

    // Should have 2 CT cells from the two mints
    assert_eq!(
        scan_results[0].cells.len(),
        2,
        "Should have 2 CT cells from consecutive mints"
    );

    let total_amount: u64 = scan_results[0].cells.iter().map(|c| c.amount).sum();
    assert_eq!(
        total_amount,
        mint_amount_1 + mint_amount_2,
        "Total amount should be {} + {} = {}",
        mint_amount_1,
        mint_amount_2,
        mint_amount_1 + mint_amount_2
    );

    println!(
        "Verified: {} CT cells with total {} tokens",
        scan_results[0].cells.len(),
        total_amount
    );
    println!("\n=== Consecutive mints test PASSED ===");
}

/// Test that mint followed by transfer works correctly.
///
/// This is a regression test for the bug where:
/// 1. Mint consumed a funding cell but didn't remove it from store
/// 2. Transfer tried to use the same (now spent) funding cell
/// 3. Transaction failed with "Unknown OutPoint"
///
/// The test verifies:
/// 1. Mint succeeds and creates a CT cell
/// 2. Transfer uses a DIFFERENT funding cell (simulating correct cleanup)
/// 3. Both transactions succeed on-chain
#[test]
fn test_mint_then_transfer_uses_separate_funding() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (issuer_store, _temp1) = create_temp_store();
    let (recipient_store, _temp2) = create_temp_store();

    println!("\n=== Testing mint-then-transfer with separate funding cells ===\n");

    // Create accounts
    let issuer = Account::new_random(0, "Issuer".to_string());
    let recipient = Account::new_random(1, "Recipient".to_string());

    // Fund issuer for genesis
    let genesis_funding = fund_account_with_stealth(env, &issuer, 350_00000000u64)
        .expect("Genesis funding should succeed");

    let issuer_stealth_address = {
        let view_pub = issuer.view_public_key().serialize();
        let spend_pub = issuer.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    // Genesis
    let genesis_params = GenesisParams {
        issuer_stealth_address: issuer_stealth_address.clone(),
        supply_cap: 1_000_000,
        flags: MINTABLE,
    };

    let built_genesis = build_genesis_transaction(&config, genesis_params, genesis_funding.clone())
        .expect("Genesis should succeed");
    let token_id = built_genesis.token_id;
    let ct_info_lock_args = built_genesis.ct_info_lock_args.clone();

    let signed_genesis = sign_genesis_transaction(
        built_genesis,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &genesis_funding.lock_script_args,
    )
    .expect("Signing should succeed");

    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let genesis_hash = client
        .send_transaction(signed_genesis, None)
        .expect("Genesis should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    println!("Token created: 0x{}", hex::encode(&token_id[..8]));

    // Fund issuer with TWO cells: one for mint, one for transfer
    println!("\nFunding issuer with separate cells for mint and transfer...");
    let mint_funding = fund_account_with_stealth(env, &issuer, 300_00000000u64)
        .expect("Mint funding should succeed");
    let transfer_funding = fund_account_with_stealth(env, &issuer, 300_00000000u64)
        .expect("Transfer funding should succeed");

    assert_ne!(
        mint_funding.out_point, transfer_funding.out_point,
        "Funding cells should be different"
    );

    // Mint 10000 tokens to issuer
    println!("\nMinting 10000 tokens...");
    let mint_amount = 10000u64; // Integer amount, NOT 10000 * 10^8

    let mut ct_info_out_point = Vec::with_capacity(36);
    ct_info_out_point.extend_from_slice(genesis_hash.as_bytes());
    ct_info_out_point.extend_from_slice(&0u32.to_le_bytes());

    let mint_params = MintParams {
        ct_info_cell: CtInfoCellInput {
            out_point: ct_info_out_point,
            lock_script_args: ct_info_lock_args.clone(),
            data: obscell_wallet::domain::ct_info::CtInfoData::new(0, 1_000_000, MINTABLE),
            capacity: 230_00000000,
        },
        token_id,
        mint_amount,
        recipient_stealth_address: issuer_stealth_address.clone(),
        funding_cell: mint_funding.clone(),
    };

    let built_mint =
        build_mint_transaction(&config, mint_params).expect("Mint build should succeed");
    let mint_hash = built_mint.tx_hash.clone();

    let signed_mint = sign_mint_transaction(
        built_mint,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &ct_info_lock_args,
        &mint_funding.lock_script_args,
    )
    .expect("Mint signing should succeed");

    client
        .send_transaction(signed_mint, None)
        .expect("Mint should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    println!(
        "Minted {} tokens, tx=0x{}",
        mint_amount,
        hex::encode(mint_hash.as_bytes())
    );

    // Scan for the minted CT cell
    let issuer_scanner = Scanner::new(config.clone(), issuer_store);
    let scan_results = issuer_scanner
        .scan_ct_cells(std::slice::from_ref(&issuer))
        .expect("Scan should succeed");

    assert_eq!(
        scan_results[0].cells.len(),
        1,
        "Issuer should have 1 CT cell"
    );
    let ct_cell = scan_results[0].cells[0].clone();
    assert_eq!(
        ct_cell.amount, mint_amount,
        "CT cell should have correct amount"
    );

    println!(
        "Found CT cell: amount={}, out_point=0x{}",
        ct_cell.amount,
        hex::encode(&ct_cell.out_point[..8])
    );

    // Transfer 123 tokens to recipient (with change)
    println!("\nTransferring 123 tokens to recipient...");
    let transfer_amount = 123u64;

    let recipient_stealth_address = {
        let view_pub = recipient.view_public_key().serialize();
        let spend_pub = recipient.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    use obscell_wallet::domain::ct_tx_builder::CtTxBuilder;

    let built_transfer = CtTxBuilder::new(config.clone(), ct_cell.type_script_args.clone())
        .add_input(ct_cell.clone())
        .add_output(recipient_stealth_address, transfer_amount)
        .funding_cell(transfer_funding.clone()) // DIFFERENT funding cell!
        .build(&issuer)
        .expect("Transfer build should succeed");

    let signed_transfer = CtTxBuilder::sign(
        built_transfer,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &[ct_cell],
        Some(&transfer_funding.lock_script_args),
    )
    .expect("Transfer signing should succeed");

    // This is the critical test: transfer should NOT fail with "Unknown OutPoint"
    // because we're using a different funding cell than the mint
    let transfer_result = client.send_transaction(signed_transfer, None);
    assert!(
        transfer_result.is_ok(),
        "Transfer should succeed (funding cell should be different from mint): {:?}",
        transfer_result.err()
    );

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    println!(
        "Transfer succeeded: {} tokens, tx=0x{}",
        transfer_amount,
        hex::encode(transfer_result.unwrap().as_bytes())
    );

    // Verify recipient received tokens
    let recipient_scanner = Scanner::new(config.clone(), recipient_store);
    let recipient_results = recipient_scanner
        .scan_ct_cells(std::slice::from_ref(&recipient))
        .expect("Recipient scan should succeed");

    assert_eq!(
        recipient_results[0].cells.len(),
        1,
        "Recipient should have 1 CT cell"
    );
    assert_eq!(
        recipient_results[0].cells[0].amount, transfer_amount,
        "Recipient should have {} tokens",
        transfer_amount
    );

    println!(
        "Recipient verified: {} tokens",
        recipient_results[0].cells[0].amount
    );
    println!("\n=== Mint-then-transfer test PASSED ===");
}

/// Test CT token multiple consecutive transfers after mint.
///
/// This test validates the 72-byte cell data format fix for the blinding factor
/// propagation issue. The core problem was:
/// - Mint cells have blinding = 0 (enforced by ct-info-type contract)
/// - Transfer creates change cells with non-zero blinding factors
/// - Scanner was incorrectly hardcoding blinding = 0 for ALL cells
/// - Second transfer failed because sum(C_in) != sum(C_out) when blinding mismatched
///
/// With the 72-byte format, change cells now store encrypted(amount || blinding),
/// allowing the scanner to correctly recover the blinding factor for subsequent transfers.
///
/// Flow:
/// 1. Issuer mints 1000 tokens to Alice
/// 2. Alice transfers 300 to Bob (creates 700 change for Alice)
/// 3. Alice transfers 200 to Carol using her change cell (creates 500 change)
/// 4. Verify final balances: Alice=500, Bob=300, Carol=200
#[test]
fn test_ct_multiple_transfers_after_mint() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (alice_store, _alice_temp) = create_temp_store();
    let (bob_store, _bob_temp) = create_temp_store();
    let (carol_store, _carol_temp) = create_temp_store();

    // Create accounts
    let issuer = Account::new_random(0, "Issuer".to_string());
    let alice = Account::new_random(1, "Alice".to_string());
    let bob = Account::new_random(2, "Bob".to_string());
    let carol = Account::new_random(3, "Carol".to_string());

    println!("=== Testing Multiple Consecutive Transfers After Mint ===");
    println!("This test validates the 72-byte format fix for blinding factor propagation.");
    println!("Issuer: {}", &issuer.stealth_address()[..32]);
    println!("Alice: {}", &alice.stealth_address()[..32]);
    println!("Bob: {}", &bob.stealth_address()[..32]);
    println!("Carol: {}", &carol.stealth_address()[..32]);

    // ========================================================================
    // Step 1: Create token and mint to Alice
    // ========================================================================
    println!("\nStep 1: Creating token and minting 1000 tokens to Alice...");

    let funding_cell =
        fund_account_with_stealth(env, &issuer, 350_00000000u64).expect("Funding should succeed");

    let issuer_stealth_address = {
        let view_pub = issuer.view_public_key().serialize();
        let spend_pub = issuer.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let genesis_params = GenesisParams {
        supply_cap: 10_000,
        flags: MINTABLE,
        issuer_stealth_address,
    };

    let genesis_tx = build_genesis_transaction(&config, genesis_params, funding_cell.clone())
        .expect("Genesis should succeed");

    let token_id = genesis_tx.token_id;
    let ct_info_lock_args = genesis_tx.ct_info_lock_args.clone();

    let signed_genesis = sign_genesis_transaction(
        genesis_tx,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &funding_cell.lock_script_args,
    )
    .expect("Signing genesis should succeed");

    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let genesis_hash = client
        .send_transaction(signed_genesis, None)
        .expect("Genesis should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Mint 1000 tokens to Alice
    let mint_amount = 1000u64;

    let mint_funding_cell = fund_account_with_stealth(env, &issuer, 350_00000000u64)
        .expect("Mint funding should succeed");

    let mut ct_info_out_point = Vec::with_capacity(36);
    ct_info_out_point.extend_from_slice(genesis_hash.as_bytes());
    ct_info_out_point.extend_from_slice(&0u32.to_le_bytes());

    let alice_stealth_address = {
        let view_pub = alice.view_public_key().serialize();
        let spend_pub = alice.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let mint_params = MintParams {
        ct_info_cell: CtInfoCellInput {
            out_point: ct_info_out_point,
            lock_script_args: ct_info_lock_args.clone(),
            data: obscell_wallet::domain::ct_info::CtInfoData::new(0, 10_000, MINTABLE),
            capacity: 230_00000000,
        },
        token_id,
        mint_amount,
        recipient_stealth_address: alice_stealth_address,
        funding_cell: mint_funding_cell.clone(),
    };

    let built_mint = build_mint_transaction(&config, mint_params).expect("Mint should succeed");

    let signed_mint = sign_mint_transaction(
        built_mint,
        &issuer,
        &issuer.spend_secret_key_for_test(),
        &ct_info_lock_args,
        &mint_funding_cell.lock_script_args,
    )
    .expect("Signing mint should succeed");

    let mint_hash = client
        .send_transaction(signed_mint, None)
        .expect("Mint should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    println!(
        "Alice received {} tokens, mint_tx=0x{}",
        mint_amount,
        hex::encode(mint_hash.as_bytes())
    );

    // ========================================================================
    // Step 2: Alice scans and finds her CT cell (from mint)
    // ========================================================================
    println!("\nStep 2: Alice scanning for CT cells...");

    let alice_scanner = Scanner::new(config.clone(), alice_store);
    let alice_results = alice_scanner
        .scan_ct_cells(&[alice.clone()])
        .expect("Alice scan should succeed");

    assert_eq!(
        alice_results[0].cells.len(),
        1,
        "Alice should have 1 CT cell"
    );
    let alice_mint_cell = alice_results[0].cells[0].clone();

    println!(
        "Alice found CT cell from mint: amount={}, out_point=0x{}",
        alice_mint_cell.amount,
        hex::encode(&alice_mint_cell.out_point[..8])
    );

    // Verify the mint cell amount
    assert_eq!(
        alice_mint_cell.amount, mint_amount,
        "Mint cell should have {} tokens",
        mint_amount
    );

    // ========================================================================
    // Step 3: First transfer - Alice sends 300 tokens to Bob
    // ========================================================================
    println!("\nStep 3: Alice transferring 300 tokens to Bob...");
    let transfer1_amount = 300u64;
    let expected_change1 = mint_amount - transfer1_amount; // 700

    let transfer1_funding = fund_account_with_stealth(env, &alice, 350_00000000u64)
        .expect("Transfer1 funding should succeed");

    use obscell_wallet::domain::ct_tx_builder::CtTxBuilder;

    let bob_stealth_address = {
        let view_pub = bob.view_public_key().serialize();
        let spend_pub = bob.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let built_transfer1 =
        CtTxBuilder::new(config.clone(), alice_mint_cell.type_script_args.clone())
            .add_input(alice_mint_cell.clone())
            .add_output(bob_stealth_address, transfer1_amount)
            .funding_cell(transfer1_funding.clone())
            .build(&alice)
            .expect("Building transfer1 should succeed");

    let signed_transfer1 = CtTxBuilder::sign(
        built_transfer1,
        &alice,
        &alice.spend_secret_key_for_test(),
        &[alice_mint_cell.clone()],
        Some(&transfer1_funding.lock_script_args),
    )
    .expect("Signing transfer1 should succeed");

    let transfer1_hash = client
        .send_transaction(signed_transfer1, None)
        .expect("Transfer1 should succeed");

    println!(
        "Transfer1 sent: Alice -> Bob {} tokens, tx=0x{}",
        transfer1_amount,
        hex::encode(transfer1_hash.as_bytes())
    );

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // ========================================================================
    // Step 4: Alice re-scans to find her change cell (72-byte format!)
    // ========================================================================
    println!("\nStep 4: Alice re-scanning for change cell...");

    // Use fresh store to avoid caching issues
    let (alice_store2, _alice_temp2) = create_temp_store();
    let alice_scanner2 = Scanner::new(config.clone(), alice_store2);
    let alice_results2 = alice_scanner2
        .scan_ct_cells(&[alice.clone()])
        .expect("Alice rescan should succeed");

    assert_eq!(
        alice_results2[0].cells.len(),
        1,
        "Alice should have 1 change cell"
    );
    let alice_change_cell = alice_results2[0].cells[0].clone();

    println!(
        "Alice found change cell: amount={}, out_point=0x{}",
        alice_change_cell.amount,
        hex::encode(&alice_change_cell.out_point[..8])
    );

    assert_eq!(
        alice_change_cell.amount, expected_change1,
        "Change cell should have {} tokens",
        expected_change1
    );

    // ========================================================================
    // Step 5: CRITICAL - Second transfer using the change cell!
    // This is the transfer that was FAILING before the 72-byte format fix.
    // ========================================================================
    println!("\nStep 5: [CRITICAL] Alice transferring 200 tokens to Carol using change cell...");
    println!(
        "This transfer uses the change cell from transfer1, which has a NON-ZERO blinding factor."
    );
    println!("Before the 72-byte format fix, this would fail with InputOutputSumMismatch (error code 7).");

    let transfer2_amount = 200u64;
    let expected_change2 = expected_change1 - transfer2_amount; // 500

    let transfer2_funding = fund_account_with_stealth(env, &alice, 350_00000000u64)
        .expect("Transfer2 funding should succeed");

    let carol_stealth_address = {
        let view_pub = carol.view_public_key().serialize();
        let spend_pub = carol.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let built_transfer2 =
        CtTxBuilder::new(config.clone(), alice_change_cell.type_script_args.clone())
            .add_input(alice_change_cell.clone())
            .add_output(carol_stealth_address, transfer2_amount)
            .funding_cell(transfer2_funding.clone())
            .build(&alice)
            .expect("Building transfer2 should succeed");

    let signed_transfer2 = CtTxBuilder::sign(
        built_transfer2,
        &alice,
        &alice.spend_secret_key_for_test(),
        &[alice_change_cell.clone()],
        Some(&transfer2_funding.lock_script_args),
    )
    .expect("Signing transfer2 should succeed");

    // THE CRITICAL ASSERTION: This transfer MUST succeed!
    let transfer2_result = client.send_transaction(signed_transfer2, None);
    assert!(
        transfer2_result.is_ok(),
        "CRITICAL: Transfer2 (using change cell) should succeed! Error: {:?}\n\
         This failure indicates the blinding factor was not correctly propagated.\n\
         The 72-byte format fix should ensure change cells store encrypted blinding factors.",
        transfer2_result.err()
    );

    let transfer2_hash = transfer2_result.unwrap();
    println!(
        "Transfer2 SUCCESS: Alice -> Carol {} tokens, tx=0x{}",
        transfer2_amount,
        hex::encode(transfer2_hash.as_bytes())
    );

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // ========================================================================
    // Step 6: Verify all final balances
    // ========================================================================
    println!("\nStep 6: Verifying final balances...");

    // Verify Bob received 300 tokens
    let bob_scanner = Scanner::new(config.clone(), bob_store);
    let bob_results = bob_scanner
        .scan_ct_cells(&[bob.clone()])
        .expect("Bob scan should succeed");

    assert_eq!(bob_results[0].cells.len(), 1, "Bob should have 1 CT cell");
    assert_eq!(
        bob_results[0].cells[0].amount, transfer1_amount,
        "Bob should have {} tokens",
        transfer1_amount
    );

    println!(
        "Bob verified: {} tokens (from transfer1)",
        bob_results[0].cells[0].amount
    );

    // Verify Carol received 200 tokens
    let carol_scanner = Scanner::new(config.clone(), carol_store);
    let carol_results = carol_scanner
        .scan_ct_cells(&[carol.clone()])
        .expect("Carol scan should succeed");

    assert_eq!(
        carol_results[0].cells.len(),
        1,
        "Carol should have 1 CT cell"
    );
    assert_eq!(
        carol_results[0].cells[0].amount, transfer2_amount,
        "Carol should have {} tokens",
        transfer2_amount
    );

    println!(
        "Carol verified: {} tokens (from transfer2)",
        carol_results[0].cells[0].amount
    );

    // Verify Alice has final change (500 tokens)
    let (alice_store3, _alice_temp3) = create_temp_store();
    let alice_scanner3 = Scanner::new(config.clone(), alice_store3);
    let alice_results3 = alice_scanner3
        .scan_ct_cells(&[alice.clone()])
        .expect("Alice final scan should succeed");

    assert_eq!(
        alice_results3[0].cells.len(),
        1,
        "Alice should have 1 final change cell"
    );
    assert_eq!(
        alice_results3[0].cells[0].amount, expected_change2,
        "Alice should have {} tokens remaining",
        expected_change2
    );

    println!(
        "Alice verified: {} tokens (final change)",
        alice_results3[0].cells[0].amount
    );

    // ========================================================================
    // Summary
    // ========================================================================
    println!("\n=== Multiple Transfers After Mint Test PASSED ===");
    println!("Token ID: 0x{}", hex::encode(&token_id[..8]));
    println!("Flow:");
    println!("  1. Mint: {} tokens to Alice", mint_amount);
    println!(
        "  2. Transfer1: Alice -> Bob {} tokens (Alice change: {})",
        transfer1_amount, expected_change1
    );
    println!(
        "  3. Transfer2: Alice -> Carol {} tokens (Alice change: {})",
        transfer2_amount, expected_change2
    );
    println!("Final balances:");
    println!("  - Alice: {} tokens", expected_change2);
    println!("  - Bob: {} tokens", transfer1_amount);
    println!("  - Carol: {} tokens", transfer2_amount);
    println!(
        "  - Total: {} tokens (matches mint amount)",
        expected_change2 + transfer1_amount + transfer2_amount
    );
}
