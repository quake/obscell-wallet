//! Complete user flow integration tests.
//!
//! Tests the full workflow using domain layer components:
//! - Account creation and management
//! - Scanning for stealth cells
//! - Building and signing stealth transactions
//! - Transaction history tracking

use tempfile::TempDir;

use super::devnet::DevNet;
use super::TestEnv;

// Re-export wallet types for testing
use obscell_wallet::config::{
    CellDepConfig, CellDepsConfig, Config, ContractConfig, NetworkConfig,
};
use obscell_wallet::domain::account::Account;
use obscell_wallet::infra::scanner::Scanner;
use obscell_wallet::infra::store::Store;

/// Create a test config pointing to the devnet with deployed contracts.
fn create_test_config(env: &TestEnv) -> Config {
    let (stealth_lock_tx_hash, stealth_lock_index) = env.stealth_lock_cell_dep();
    let type_id_hash = env.stealth_lock_code_hash();
    let (ckb_auth_tx_hash, ckb_auth_index) = env.ckb_auth_cell_dep();
    let ckb_auth_data_hash = env.ckb_auth_data_hash();

    Config {
        network: NetworkConfig {
            name: "devnet".to_string(),
            rpc_url: DevNet::RPC_URL.to_string(),
            indexer_url: DevNet::RPC_URL.to_string(),
        },
        contracts: ContractConfig {
            stealth_lock_code_hash: format!("0x{}", hex::encode(type_id_hash.as_bytes())),
            ct_token_code_hash: "0x0".repeat(64),
            ct_info_code_hash: "0x0".repeat(64),
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
                tx_hash: "0x".to_string() + &"0".repeat(64),
                index: 0,
                ..Default::default()
            },
            ct_info: CellDepConfig {
                tx_hash: "0x".to_string() + &"0".repeat(64),
                index: 0,
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

#[test]
fn test_account_creation_and_stealth_address() {
    let _env = TestEnv::get();

    // Create accounts
    let alice = Account::new(0, "Alice".to_string());
    let bob = Account::new(1, "Bob".to_string());

    // Verify accounts have valid keys
    let alice_stealth_addr = alice.stealth_address();
    let bob_stealth_addr = bob.stealth_address();

    // Stealth address should be 132 hex chars (66 bytes = view_pub + spend_pub)
    assert_eq!(alice_stealth_addr.len(), 132);
    assert_eq!(bob_stealth_addr.len(), 132);

    // Accounts should have different addresses
    assert_ne!(alice_stealth_addr, bob_stealth_addr);

    // Keys should be valid
    assert!(alice.view_secret_key().secret_bytes().len() == 32);
    assert!(alice.spend_secret_key().secret_bytes().len() == 32);

    println!("Alice stealth address: {}", &alice_stealth_addr[..32]);
    println!("Bob stealth address: {}", &bob_stealth_addr[..32]);
}

#[test]
fn test_scanner_finds_stealth_cells() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create an account
    let alice = Account::new(0, "Alice".to_string());

    // Fund Alice via stealth transfer
    let stealth_code_hash = env.stealth_lock_code_hash();
    let alice_view_pub = alice.view_public_key();
    let alice_spend_pub = alice.spend_public_key();

    // Generate stealth script args for Alice
    let (eph_pub, stealth_pub) =
        obscell_wallet::domain::stealth::generate_ephemeral_key(&alice_view_pub, &alice_spend_pub);
    let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
    let mut script_args = Vec::with_capacity(53);
    script_args.extend_from_slice(&eph_pub.serialize());
    script_args.extend_from_slice(&pubkey_hash[0..20]);

    // Send 200 CKB to Alice's stealth address
    let amount = 200_00000000u64;
    env.faucet
        .transfer_to_stealth(&script_args, &stealth_code_hash, amount)
        .expect("Transfer should succeed");

    // Confirm transaction
    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync()
        .expect("Should sync indexer after transfer");

    // Create scanner and scan for Alice's cells
    let scanner = Scanner::new(config, store);
    let result = scanner.full_scan(&alice).expect("Scan should succeed");

    // Verify Alice found her cell
    assert_eq!(result.stealth_cells.len(), 1, "Alice should find 1 cell");
    assert_eq!(result.total_capacity, amount, "Capacity should match");

    println!(
        "Scanner found {} cells with {} CKB total",
        result.stealth_cells.len(),
        result.total_capacity / 100_000_000
    );
}

#[test]
fn test_multi_account_scanning() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create two accounts
    let alice = Account::new(0, "Alice".to_string());
    let bob = Account::new(1, "Bob".to_string());

    let stealth_code_hash = env.stealth_lock_code_hash();

    // Fund both accounts with different amounts
    let alice_amount = 150_00000000u64;
    let bob_amount = 250_00000000u64;

    // Generate stealth args for Alice
    let (eph_pub_a, stealth_pub_a) = obscell_wallet::domain::stealth::generate_ephemeral_key(
        &alice.view_public_key(),
        &alice.spend_public_key(),
    );
    let pubkey_hash_a = ckb_hash::blake2b_256(stealth_pub_a.serialize());
    let mut alice_args = Vec::with_capacity(53);
    alice_args.extend_from_slice(&eph_pub_a.serialize());
    alice_args.extend_from_slice(&pubkey_hash_a[0..20]);

    env.faucet
        .transfer_to_stealth(&alice_args, &stealth_code_hash, alice_amount)
        .expect("Alice transfer should succeed");

    env.generate_blocks(5).expect("Should generate blocks");

    // Generate stealth args for Bob
    let (eph_pub_b, stealth_pub_b) = obscell_wallet::domain::stealth::generate_ephemeral_key(
        &bob.view_public_key(),
        &bob.spend_public_key(),
    );
    let pubkey_hash_b = ckb_hash::blake2b_256(stealth_pub_b.serialize());
    let mut bob_args = Vec::with_capacity(53);
    bob_args.extend_from_slice(&eph_pub_b.serialize());
    bob_args.extend_from_slice(&pubkey_hash_b[0..20]);

    env.faucet
        .transfer_to_stealth(&bob_args, &stealth_code_hash, bob_amount)
        .expect("Bob transfer should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync()
        .expect("Should sync indexer after Bob transfer");

    // Scan for both accounts
    let scanner = Scanner::new(config, store);
    let results = scanner
        .scan_all_accounts(&[alice.clone(), bob.clone()])
        .expect("Scan should succeed");

    // Verify results
    assert_eq!(results.len(), 2, "Should have results for 2 accounts");

    let alice_result = results.iter().find(|r| r.account_id == 0).unwrap();
    let bob_result = results.iter().find(|r| r.account_id == 1).unwrap();

    assert_eq!(alice_result.cells.len(), 1, "Alice should have 1 cell");
    assert_eq!(alice_result.total_capacity, alice_amount);

    assert_eq!(bob_result.cells.len(), 1, "Bob should have 1 cell");
    assert_eq!(bob_result.total_capacity, bob_amount);

    println!(
        "Multi-account scan: Alice={} CKB, Bob={} CKB",
        alice_result.total_capacity / 100_000_000,
        bob_result.total_capacity / 100_000_000
    );
}

#[test]
fn test_account_receives_multiple_transfers() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create account
    let alice = Account::new(0, "Alice".to_string());
    let stealth_code_hash = env.stealth_lock_code_hash();

    // Send multiple transfers to Alice (each with unique ephemeral key)
    let amounts = [100_00000000u64, 200_00000000u64, 300_00000000u64];

    for amount in &amounts {
        let (eph_pub, stealth_pub) = obscell_wallet::domain::stealth::generate_ephemeral_key(
            &alice.view_public_key(),
            &alice.spend_public_key(),
        );
        let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
        let mut args = Vec::with_capacity(53);
        args.extend_from_slice(&eph_pub.serialize());
        args.extend_from_slice(&pubkey_hash[0..20]);

        env.faucet
            .transfer_to_stealth(&args, &stealth_code_hash, *amount)
            .expect("Transfer should succeed");

        // Generate enough blocks to fully confirm the transaction before sending next one
        // CKB proposal window requires ~4 blocks, we use 10 for safety
        env.generate_blocks(10).expect("Should generate blocks");
        env.wait_for_indexer_sync()
            .expect("Should sync indexer after transfer");
    }

    // Final confirmation
    env.generate_blocks(5).expect("Should generate blocks");
    env.wait_for_indexer_sync()
        .expect("Should sync indexer after final confirmation");

    // Scan
    let scanner = Scanner::new(config, store);
    let result = scanner.full_scan(&alice).expect("Scan should succeed");

    // Verify
    let expected_total: u64 = amounts.iter().sum();
    assert_eq!(result.stealth_cells.len(), 3, "Should find 3 cells");
    assert_eq!(result.total_capacity, expected_total);

    println!(
        "Alice received {} transfers totaling {} CKB",
        result.stealth_cells.len(),
        result.total_capacity / 100_000_000
    );
}

#[test]
fn test_store_persists_cells() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create account and fund it
    let alice = Account::new(0, "Alice".to_string());
    let stealth_code_hash = env.stealth_lock_code_hash();

    let (eph_pub, stealth_pub) = obscell_wallet::domain::stealth::generate_ephemeral_key(
        &alice.view_public_key(),
        &alice.spend_public_key(),
    );
    let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
    let mut args = Vec::with_capacity(53);
    args.extend_from_slice(&eph_pub.serialize());
    args.extend_from_slice(&pubkey_hash[0..20]);

    let amount = 500_00000000u64;
    env.faucet
        .transfer_to_stealth(&args, &stealth_code_hash, amount)
        .expect("Transfer should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync()
        .expect("Should sync indexer after transfer");

    // Scan and verify cells are persisted
    let scanner = Scanner::new(config.clone(), store.clone());
    let results = scanner
        .scan_all_accounts(std::slice::from_ref(&alice))
        .expect("Scan should succeed");

    assert_eq!(results[0].cells.len(), 1);
    assert_eq!(results[0].new_cells.len(), 1); // First scan, all cells are new

    // Load cells from store directly
    let stored_cells = store.get_stealth_cells(0).expect("Should load cells");
    assert_eq!(stored_cells.len(), 1);
    assert_eq!(stored_cells[0].capacity, amount);

    // Scan again - should not have new cells
    let results2 = scanner
        .scan_all_accounts(&[alice])
        .expect("Second scan should succeed");

    assert_eq!(results2[0].cells.len(), 1);
    assert_eq!(results2[0].new_cells.len(), 0); // No new cells

    println!("Store correctly persists cells across scans");
}

#[test]
fn test_tx_history_recorded_on_receive() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create account
    let alice = Account::new(0, "Alice".to_string());
    let stealth_code_hash = env.stealth_lock_code_hash();

    // Fund Alice
    let (eph_pub, stealth_pub) = obscell_wallet::domain::stealth::generate_ephemeral_key(
        &alice.view_public_key(),
        &alice.spend_public_key(),
    );
    let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
    let mut args = Vec::with_capacity(53);
    args.extend_from_slice(&eph_pub.serialize());
    args.extend_from_slice(&pubkey_hash[0..20]);

    let amount = 123_00000000u64;
    env.faucet
        .transfer_to_stealth(&args, &stealth_code_hash, amount)
        .expect("Transfer should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync()
        .expect("Should sync indexer after transfer");

    // Scan
    let scanner = Scanner::new(config, store.clone());
    scanner
        .scan_all_accounts(&[alice])
        .expect("Scan should succeed");

    // Check transaction history
    let history = store.get_tx_history(0).expect("Should load history");
    assert_eq!(history.len(), 1, "Should have 1 tx record");

    let record = &history[0];
    assert_eq!(record.direction(), "Receive");
    assert_eq!(record.amount_ckb(), Some(123.0));

    println!(
        "Transaction history recorded: {} {} CKB",
        record.direction(),
        record.amount_ckb().unwrap()
    );
}

#[test]
fn test_alice_sends_to_bob_full_flow() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create accounts
    let alice = Account::new(0, "Alice".to_string());
    let bob = Account::new(1, "Bob".to_string());

    let stealth_code_hash = env.stealth_lock_code_hash();

    // Step 1: Fund Alice with 500 CKB via stealth
    println!("Step 1: Funding Alice with 500 CKB...");
    let (eph_pub, stealth_pub) = obscell_wallet::domain::stealth::generate_ephemeral_key(
        &alice.view_public_key(),
        &alice.spend_public_key(),
    );
    let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
    let mut alice_args = Vec::with_capacity(53);
    alice_args.extend_from_slice(&eph_pub.serialize());
    alice_args.extend_from_slice(&pubkey_hash[0..20]);

    let initial_amount = 500_00000000u64;
    env.faucet
        .transfer_to_stealth(&alice_args, &stealth_code_hash, initial_amount)
        .expect("Funding Alice should succeed");

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync()
        .expect("Should sync indexer after funding");

    // Step 2: Alice scans and verifies balance
    println!("Step 2: Alice scanning for cells...");
    let scanner = Scanner::new(config.clone(), store.clone());
    let alice_scan = scanner
        .full_scan(&alice)
        .expect("Alice scan should succeed");

    assert_eq!(
        alice_scan.stealth_cells.len(),
        1,
        "Alice should have 1 cell"
    );
    assert_eq!(
        alice_scan.total_capacity, initial_amount,
        "Alice should have 500 CKB"
    );
    println!(
        "Alice has {} CKB in {} cells",
        alice_scan.total_capacity / 100_000_000,
        alice_scan.stealth_cells.len()
    );

    // Step 3: Alice builds transaction to send 100 CKB to Bob
    println!("Step 3: Alice sending 100 CKB to Bob...");
    let send_amount = 100_00000000u64;

    // Build Bob's stealth address (66 bytes = view_pub || spend_pub)
    let bob_stealth_address = {
        let view_pub = bob.view_public_key().serialize();
        let spend_pub = bob.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    // Use StealthTxBuilder
    use obscell_wallet::domain::tx_builder::StealthTxBuilder;

    let builder = StealthTxBuilder::new(config.clone())
        .add_inputs(alice_scan.stealth_cells.clone())
        .add_output(bob_stealth_address, send_amount);

    let built_tx = builder.build(&alice).expect("Building tx should succeed");
    println!(
        "Transaction built, hash: 0x{}",
        hex::encode(built_tx.tx_hash.as_bytes())
    );

    // Sign the transaction
    let signed_tx = StealthTxBuilder::sign(built_tx, &alice, &alice_scan.stealth_cells)
        .expect("Signing should succeed");

    // Submit the transaction
    use ckb_sdk::CkbRpcClient;
    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let tx_hash = client
        .send_transaction(signed_tx.clone(), None)
        .expect("Sending tx should succeed");

    println!("Transaction sent: 0x{}", hex::encode(tx_hash.as_bytes()));

    // Confirm
    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync()
        .expect("Should sync indexer after tx confirmation");

    // Step 4: Bob scans and verifies he received 100 CKB
    println!("Step 4: Bob scanning for cells...");
    let (bob_store, _bob_temp) = create_temp_store();
    let bob_scanner = Scanner::new(config.clone(), bob_store);
    let bob_scan = bob_scanner
        .full_scan(&bob)
        .expect("Bob scan should succeed");

    assert_eq!(bob_scan.stealth_cells.len(), 1, "Bob should have 1 cell");
    assert_eq!(
        bob_scan.total_capacity, send_amount,
        "Bob should have 100 CKB"
    );
    println!("Bob received {} CKB", bob_scan.total_capacity / 100_000_000);

    // Step 5: Alice scans again and verifies remaining balance
    println!("Step 5: Alice verifying remaining balance...");
    scanner.clear_cursor().expect("Should clear cursor");
    let alice_final = scanner
        .full_scan(&alice)
        .expect("Alice final scan should succeed");

    // Alice should have change cell (500 - 100 - fee = ~399 CKB)
    // The exact amount depends on the fee and minimum cell capacity
    let expected_min = 300_00000000u64; // At least 300 CKB remaining
    assert!(
        alice_final.total_capacity >= expected_min,
        "Alice should have at least {} CKB, got {}",
        expected_min / 100_000_000,
        alice_final.total_capacity / 100_000_000
    );

    println!(
        "Final balances: Alice={} CKB ({} cells), Bob={} CKB ({} cells)",
        alice_final.total_capacity / 100_000_000,
        alice_final.stealth_cells.len(),
        bob_scan.total_capacity / 100_000_000,
        bob_scan.stealth_cells.len()
    );

    println!("Full flow test completed successfully!");
}
