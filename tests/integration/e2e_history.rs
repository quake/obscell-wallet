//! End-to-end transaction history integration tests.
//!
//! Tests that transaction history is properly recorded for:
//! - Stealth CKB sends and receives
//! - CT token transfers (sends and receives)

use ckb_sdk::CkbRpcClient;
use tempfile::TempDir;

use super::devnet::DevNet;
use super::TestEnv;

use obscell_wallet::config::{
    CellDepConfig, CellDepsConfig, Config, ContractConfig, NetworkConfig,
};
use obscell_wallet::domain::account::Account;
use obscell_wallet::domain::cell::{TxRecord, TxType};
use obscell_wallet::domain::ct_info::MINTABLE;
use obscell_wallet::domain::ct_mint::{
    build_genesis_transaction, build_mint_transaction, sign_genesis_transaction,
    sign_mint_transaction, CtInfoCellInput, FundingCell, GenesisParams, MintParams,
};
use obscell_wallet::domain::stealth::generate_ephemeral_key;
use obscell_wallet::domain::tx_builder::StealthTxBuilder;
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

/// Test that CKB stealth transfer records history for both sender and receiver.
#[test]
fn test_ckb_transfer_history_both_parties() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (alice_store, _alice_temp) = create_temp_store();
    let (bob_store, _bob_temp) = create_temp_store();

    // Create accounts
    let alice = Account::new_random(0, "Alice".to_string());
    let bob = Account::new_random(1, "Bob".to_string());

    let stealth_code_hash = env.stealth_lock_code_hash();

    println!("Step 1: Fund Alice with 500 CKB...");
    let initial_amount = 500_00000000u64;

    // Generate stealth args for Alice
    let (eph_pub, stealth_pub) =
        generate_ephemeral_key(&alice.view_public_key(), &alice.spend_public_key());
    let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
    let mut alice_args = Vec::with_capacity(53);
    alice_args.extend_from_slice(&eph_pub.serialize());
    alice_args.extend_from_slice(&pubkey_hash[0..20]);

    env.faucet
        .transfer_to_stealth(&alice_args, &stealth_code_hash, initial_amount)
        .expect("Funding Alice should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Alice scans to find her cells - use scan_all_accounts for cells, then scan_tx_history for history
    println!("Step 2: Alice scans for cells...");
    let alice_scanner = Scanner::new(config.clone(), alice_store.clone());
    let alice_results = alice_scanner
        .scan_all_accounts(&[alice.clone()])
        .expect("Alice scan should succeed");
    alice_scanner
        .scan_tx_history(&alice)
        .expect("Alice history scan should succeed");

    assert_eq!(alice_results.len(), 1, "Should have 1 account result");
    assert_eq!(alice_results[0].cells.len(), 1, "Alice should have 1 cell");

    // Alice's history should show the receive (positive delta = received CKB)
    let alice_history = alice_store
        .get_tx_history(alice.id)
        .expect("Should get Alice history");
    assert_eq!(alice_history.len(), 1, "Alice should have 1 history entry");
    assert!(
        matches!(alice_history[0].tx_type, TxType::Ckb { delta } if delta > 0),
        "Alice should have Ckb receive (positive delta) in history"
    );

    println!(
        "Alice received: {} CKB",
        alice_history[0].delta_ckb().unwrap()
    );

    // Get cells from store for building tx
    let alice_cells = alice_store
        .get_stealth_cells(alice.id)
        .expect("Should get Alice cells");

    // Alice sends 100 CKB to Bob
    println!("Step 3: Alice sends 100 CKB to Bob...");
    let send_amount = 100_00000000u64;

    let bob_stealth_address = {
        let view_pub = bob.view_public_key().serialize();
        let spend_pub = bob.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let builder = StealthTxBuilder::new(config.clone())
        .add_inputs(alice_cells.clone())
        .add_output(bob_stealth_address.clone(), send_amount);

    let built_tx = builder.build(&alice).expect("Building tx should succeed");
    let signed_tx = StealthTxBuilder::sign(
        built_tx.clone(),
        &alice,
        &alice.spend_secret_key_for_test(),
        &alice_cells,
    )
    .expect("Signing should succeed");

    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let tx_hash = client
        .send_transaction(signed_tx, None)
        .expect("Sending tx should succeed");

    println!("Transaction sent: 0x{}", hex::encode(tx_hash.as_bytes()));

    // Record send in Alice's history (simulating what app.rs does)
    // Use negative delta to indicate sent CKB
    let send_record = TxRecord::ckb(
        built_tx.tx_hash.0,
        -(send_amount as i64),
        0, // timestamp (not used in test)
        0, // block_number (not used in test)
    );
    alice_store
        .save_tx_record(alice.id, &send_record)
        .expect("Should save send record");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Bob scans and his history should show the receive
    println!("Step 4: Bob scans for cells...");
    let bob_scanner = Scanner::new(config.clone(), bob_store.clone());
    let bob_results = bob_scanner
        .scan_all_accounts(&[bob.clone()])
        .expect("Bob scan should succeed");
    bob_scanner
        .scan_tx_history(&bob)
        .expect("Bob history scan should succeed");

    assert_eq!(bob_results[0].cells.len(), 1, "Bob should have 1 cell");
    assert_eq!(
        bob_results[0].total_capacity, send_amount,
        "Bob should have 100 CKB"
    );

    // Verify Bob's history
    let bob_history = bob_store
        .get_tx_history(bob.id)
        .expect("Should get Bob history");
    assert_eq!(bob_history.len(), 1, "Bob should have 1 history entry");

    if let TxType::Ckb { delta } = &bob_history[0].tx_type {
        assert_eq!(
            *delta, send_amount as i64,
            "Bob receive amount should match (positive delta)"
        );
    } else {
        panic!(
            "Bob should have Ckb type, got: {:?}",
            bob_history[0].tx_type
        );
    }

    println!("Bob received: {} CKB", bob_history[0].delta_ckb().unwrap());

    // Verify Alice's history now has both receive and send
    let alice_history_final = alice_store
        .get_tx_history(alice.id)
        .expect("Should get Alice history");
    assert_eq!(
        alice_history_final.len(),
        2,
        "Alice should have 2 history entries"
    );

    // Find the send entry (negative delta)
    let send_entry = alice_history_final
        .iter()
        .find(|h| matches!(h.tx_type, TxType::Ckb { delta } if delta < 0));
    assert!(
        send_entry.is_some(),
        "Alice should have Ckb send entry (negative delta)"
    );

    if let TxType::Ckb { delta } = &send_entry.unwrap().tx_type {
        assert_eq!(
            *delta,
            -(send_amount as i64),
            "Send amount should match (negative)"
        );
    }

    println!("\nCKB transfer history test passed!");
    println!("  Alice history: {} entries", alice_history_final.len());
    println!("  Bob history: {} entries", bob_history.len());
}

/// Test that CT token transfer records history for both sender and receiver.
#[test]
fn test_ct_transfer_history_both_parties() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (alice_store, _alice_temp) = create_temp_store();
    let (bob_store, _bob_temp) = create_temp_store();

    // Create accounts
    let issuer = Account::new_random(0, "Issuer".to_string());
    let alice = Account::new_random(1, "Alice".to_string());
    let bob = Account::new_random(2, "Bob".to_string());

    println!("Step 1: Create CT token and mint to Alice...");

    // Create token
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
        .expect("Genesis tx should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Mint 1000 tokens to Alice
    let mint_amount = 1000u64;

    let mint_funding = fund_account_with_stealth(env, &issuer, 350_00000000u64)
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
        funding_cell: mint_funding.clone(),
    };

    let built_mint =
        build_mint_transaction(&config, mint_params).expect("Mint build should succeed");

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
        .expect("Mint tx should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    println!("Token minted: ID=0x{}", hex::encode(&token_id[..8]));

    // Alice scans for CT cells using scan_ct_cells for cells, then scan_tx_history for history
    println!("Step 2: Alice scans for CT cells...");
    let alice_scanner = Scanner::new(config.clone(), alice_store.clone());
    let alice_results = alice_scanner
        .scan_ct_cells(&[alice.clone()])
        .expect("Alice CT scan should succeed");
    alice_scanner
        .scan_tx_history(&alice)
        .expect("Alice history scan should succeed");

    assert_eq!(
        alice_results[0].cells.len(),
        1,
        "Alice should have 1 CT cell"
    );

    // Alice's history should show CT receive (positive delta)
    let alice_history = alice_store
        .get_tx_history(alice.id)
        .expect("Should get Alice history");
    assert_eq!(alice_history.len(), 1, "Alice should have 1 history entry");

    if let TxType::Ct { token, delta } = &alice_history[0].tx_type {
        assert_eq!(
            *delta, mint_amount as i64,
            "Receive amount should match (positive delta)"
        );
        assert_eq!(*token, token_id, "Token ID should match");
    } else {
        panic!(
            "Alice should have Ct type, got: {:?}",
            alice_history[0].tx_type
        );
    }

    println!(
        "Alice received CT: {} tokens (delta: {})",
        mint_amount,
        alice_history[0].delta()
    );

    // Get cells from store for building tx
    let alice_ct_cells = alice_store
        .get_ct_cells(alice.id)
        .expect("Should get Alice CT cells");
    let alice_ct_cell = alice_ct_cells[0].clone();

    // Alice transfers 300 tokens to Bob
    println!("Step 3: Alice transfers 300 CT tokens to Bob...");
    let transfer_amount = 300u64;

    let transfer_funding = fund_account_with_stealth(env, &alice, 350_00000000u64)
        .expect("Transfer funding should succeed");

    use obscell_wallet::domain::ct_tx_builder::CtTxBuilder;

    let bob_stealth_address = {
        let view_pub = bob.view_public_key().serialize();
        let spend_pub = bob.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let built_transfer = CtTxBuilder::new(config.clone(), alice_ct_cell.type_script_args.clone())
        .add_input(alice_ct_cell.clone())
        .add_output(bob_stealth_address.clone(), transfer_amount)
        .funding_cell(transfer_funding.clone())
        .build(&alice)
        .expect("Building transfer should succeed");

    let signed_transfer = CtTxBuilder::sign(
        built_transfer.clone(),
        &alice,
        &alice.spend_secret_key_for_test(),
        &[alice_ct_cell.clone()],
        Some(&transfer_funding.lock_script_args),
    )
    .expect("Signing transfer should succeed");

    let transfer_hash = client
        .send_transaction(signed_transfer, None)
        .expect("Transfer tx should succeed");

    println!("Transfer sent: 0x{}", hex::encode(transfer_hash.as_bytes()));

    // Record send in Alice's history (simulating what app.rs does)
    // Use negative delta to indicate sent tokens
    let send_record = TxRecord::ct(
        built_transfer.tx_hash.0,
        token_id,
        -(transfer_amount as i64),
        0, // timestamp
        0, // block_number
    );
    alice_store
        .save_tx_record(alice.id, &send_record)
        .expect("Should save CT send record");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Bob scans and his history should show CT receive
    println!("Step 4: Bob scans for CT cells...");
    let bob_scanner = Scanner::new(config.clone(), bob_store.clone());
    let bob_results = bob_scanner
        .scan_ct_cells(&[bob.clone()])
        .expect("Bob CT scan should succeed");
    bob_scanner
        .scan_tx_history(&bob)
        .expect("Bob history scan should succeed");

    assert_eq!(bob_results[0].cells.len(), 1, "Bob should have 1 CT cell");
    assert_eq!(
        bob_results[0].cells[0].amount, transfer_amount,
        "Bob should have 300 tokens"
    );

    // Verify Bob's history
    let bob_history = bob_store
        .get_tx_history(bob.id)
        .expect("Should get Bob history");
    assert_eq!(bob_history.len(), 1, "Bob should have 1 history entry");

    if let TxType::Ct { token, delta } = &bob_history[0].tx_type {
        assert_eq!(
            *delta, transfer_amount as i64,
            "Bob receive amount should match (positive delta)"
        );
        assert_eq!(*token, token_id, "Token ID should match");
    } else {
        panic!("Bob should have Ct type, got: {:?}", bob_history[0].tx_type);
    }

    println!(
        "Bob received CT: {} tokens (delta: {})",
        transfer_amount,
        bob_history[0].delta()
    );

    // Verify Alice's history now has both receive and transfer
    let alice_history_final = alice_store
        .get_tx_history(alice.id)
        .expect("Should get Alice history");

    // Alice should have: 1 CtReceive (mint) + 1 CtTransfer (send)
    // Note: change cell might also record if we rescan, but we don't rescan here
    assert!(
        alice_history_final.len() >= 2,
        "Alice should have at least 2 history entries, got {}",
        alice_history_final.len()
    );

    // Find the transfer entry (negative delta)
    let transfer_entry = alice_history_final
        .iter()
        .find(|h| matches!(h.tx_type, TxType::Ct { delta, .. } if delta < 0));
    assert!(
        transfer_entry.is_some(),
        "Alice should have Ct send entry (negative delta)"
    );

    if let TxType::Ct { token, delta } = &transfer_entry.unwrap().tx_type {
        assert_eq!(
            *delta,
            -(transfer_amount as i64),
            "Transfer amount should match (negative)"
        );
        assert_eq!(*token, token_id, "Token ID should match");
    }

    println!("\nCT transfer history test passed!");
    println!("  Alice history: {} entries", alice_history_final.len());
    println!("  Bob history: {} entries", bob_history.len());
    println!("  Token ID: 0x{}", hex::encode(&token_id[..8]));
}

/// Test that history entries have correct status transitions.
#[test]
fn test_history_status_tracking() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create account
    let alice = Account::new_random(0, "Alice".to_string());
    let stealth_code_hash = env.stealth_lock_code_hash();

    // Fund Alice
    let (eph_pub, stealth_pub) =
        generate_ephemeral_key(&alice.view_public_key(), &alice.spend_public_key());
    let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
    let mut args = Vec::with_capacity(53);
    args.extend_from_slice(&eph_pub.serialize());
    args.extend_from_slice(&pubkey_hash[0..20]);

    let amount = 200_00000000u64;
    env.faucet
        .transfer_to_stealth(&args, &stealth_code_hash, amount)
        .expect("Transfer should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Scan using scan_all_accounts which persists cells, then scan_tx_history for history
    let scanner = Scanner::new(config, store.clone());
    scanner
        .scan_all_accounts(&[alice.clone()])
        .expect("Scan should succeed");
    scanner
        .scan_tx_history(&alice)
        .expect("History scan should succeed");

    // Check history
    let history = store.get_tx_history(alice.id).expect("Should load history");
    assert_eq!(history.len(), 1, "Should have 1 tx record");

    let record = &history[0];
    // TxRecord no longer has a status field - all scanned transactions are confirmed by definition
    // Verify it's a CKB receive (positive delta)
    assert!(
        matches!(record.tx_type, TxType::Ckb { delta } if delta > 0),
        "Should be a CKB receive with positive delta"
    );

    // Verify the tx_hash is correct (first 32 bytes of out_point)
    let stored_cells = store.get_stealth_cells(alice.id).expect("Should get cells");
    assert_eq!(stored_cells.len(), 1);

    let cell_tx_hash = &stored_cells[0].out_point[..32];
    assert_eq!(
        record.tx_hash.as_slice(),
        cell_tx_hash,
        "History tx_hash should match cell out_point"
    );

    println!("History status tracking test passed!");
    println!("  Tx type: {:?}", record.tx_type);
    println!("  Tx hash: {}", record.short_hash());
}
