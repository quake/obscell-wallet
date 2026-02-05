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
            indexer_url: DevNet::RPC_URL.to_string(),
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
            },
            ckb_auth: CellDepConfig {
                tx_hash: format!("0x{}", hex::encode(ckb_auth_tx_hash.as_bytes())),
                index: ckb_auth_index,
            },
            ct_token: CellDepConfig {
                tx_hash: format!("0x{}", hex::encode(ct_token_tx_hash.as_bytes())),
                index: ct_token_index,
            },
            ct_info: CellDepConfig {
                tx_hash: format!("0x{}", hex::encode(ct_info_tx_hash.as_bytes())),
                index: ct_info_index,
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
    let issuer = Account::new(0, "Issuer".to_string());
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
    let signed_tx =
        sign_genesis_transaction(built_tx.clone(), &issuer, &funding_cell.lock_script_args)
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
    let issuer = Account::new(0, "Issuer".to_string());
    let recipient = Account::new(1, "Recipient".to_string());

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

    let signed_genesis =
        sign_genesis_transaction(genesis_tx, &issuer, &funding_cell.lock_script_args)
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
        "Recipient found CT cell: amount={}, token_type=0x{}",
        ct_cell.amount,
        hex::encode(&ct_cell.token_type_hash[..8])
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
    let issuer = Account::new(0, "Issuer".to_string());
    let alice = Account::new(1, "Alice".to_string());
    let bob = Account::new(2, "Bob".to_string());

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

    let signed_genesis =
        sign_genesis_transaction(genesis_tx, &issuer, &funding_cell.lock_script_args)
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

    use obscell_wallet::domain::ct_tx_builder::CtTxBuilder;

    let bob_stealth_address = {
        let view_pub = bob.view_public_key().serialize();
        let spend_pub = bob.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let built_transfer = CtTxBuilder::new(config.clone(), token_id)
        .add_input(alice_ct_cell.clone())
        .add_output(bob_stealth_address, transfer_amount)
        .build(&alice)
        .expect("Building transfer should succeed");

    println!(
        "Transfer tx built: hash=0x{}, outputs={}",
        hex::encode(built_transfer.tx_hash.as_bytes()),
        built_transfer.tx.outputs.len()
    );

    // Sign the transfer
    let signed_transfer = CtTxBuilder::sign(built_transfer, &alice, &[alice_ct_cell])
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
        "Bob received {} tokens, token_type=0x{}",
        bob_ct_cell.amount,
        hex::encode(&bob_ct_cell.token_type_hash[..8])
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
    let issuer = Account::new(0, "Issuer".to_string());
    let alice = Account::new(1, "Alice".to_string());
    let bob = Account::new(2, "Bob".to_string());

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

    let signed_genesis =
        sign_genesis_transaction(genesis_tx, &issuer, &funding_cell.lock_script_args)
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
    let issuer = Account::new(0, "Issuer".to_string());

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

    let signed_genesis =
        sign_genesis_transaction(genesis_tx, &issuer, &funding_cell.lock_script_args)
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
    assert_eq!(ct_info_cell.token_id, token_id, "Token ID should match");
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
    let issuer = Account::new(0, "Issuer".to_string());
    let alice = Account::new(1, "Alice".to_string());

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

    let signed_genesis =
        sign_genesis_transaction(genesis_tx, &issuer, &funding_cell.lock_script_args)
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

    let issuer = Account::new(0, "Issuer".to_string());
    let alice = Account::new(1, "Alice".to_string());
    let bob = Account::new(2, "Bob".to_string());

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

    let signed_genesis =
        sign_genesis_transaction(genesis_tx, &issuer, &funding_cell.lock_script_args)
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

    let transfer_tx = CtTxBuilder::new(config.clone(), token_id)
        .add_input(alice_ct_cell.clone())
        .add_output(bob_stealth, transfer_amount)
        .build(&alice)
        .expect("Transfer should succeed");

    // Verify the transaction has 2 outputs (Bob + Alice change)
    assert_eq!(
        transfer_tx.tx.outputs.len(),
        2,
        "Transfer should have 2 outputs (recipient + change)"
    );

    let signed_transfer =
        CtTxBuilder::sign(transfer_tx, &alice, &[alice_ct_cell]).expect("Signing should succeed");

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

    let issuer = Account::new(0, "Issuer".to_string());
    let recipient = Account::new(1, "Recipient".to_string());

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

    let signed_genesis =
        sign_genesis_transaction(genesis_tx, &issuer, &funding_cell.lock_script_args)
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

    let issuer = Account::new(0, "Issuer".to_string());
    let alice = Account::new(1, "Alice".to_string());

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

    let signed_genesis =
        sign_genesis_transaction(genesis_tx, &issuer, &funding_cell.lock_script_args)
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
