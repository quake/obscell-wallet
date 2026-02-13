//! Integration test for the faucet → scan → send flow.
//!
//! This test reproduces the bug where sending after receiving from faucet
//! fails with "Invalid OutPoint" error due to cells having zero tx_hash.

use tempfile::TempDir;

use super::TestEnv;
use super::devnet::DevNet;

use obscell_wallet::config::{
    CellDepConfig, CellDepsConfig, Config, ContractConfig, NetworkConfig,
};
use obscell_wallet::domain::account::Account;
use obscell_wallet::domain::tx_builder::StealthTxBuilder;
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
            scan_start_block: 0,
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

/// Test the complete flow: faucet -> scan -> verify out_point -> send
///
/// This test specifically checks that:
/// 1. Cells received via faucet have valid out_points (non-zero tx_hash)
/// 2. Scanned cells can be used to build and submit transactions
#[test]
fn test_faucet_scan_send_flow() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create accounts
    let alice = Account::new_random(0, "Alice".to_string());
    let bob = Account::new_random(1, "Bob".to_string());

    let stealth_code_hash = env.stealth_lock_code_hash();

    // Step 1: Fund Alice via faucet (same way the wallet UI does it)
    println!("Step 1: Funding Alice via faucet...");
    let (eph_pub, stealth_pub) = obscell_wallet::domain::stealth::generate_ephemeral_key(
        &alice.view_public_key(),
        &alice.spend_public_key(),
    );
    let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
    let mut alice_args = Vec::with_capacity(53);
    alice_args.extend_from_slice(&eph_pub.serialize());
    alice_args.extend_from_slice(&pubkey_hash[0..20]);

    let faucet_amount = 500_00000000u64; // 500 CKB
    let faucet_tx_hash = env
        .faucet
        .transfer_to_stealth(&alice_args, &stealth_code_hash, faucet_amount)
        .expect("Faucet should succeed");

    println!(
        "  Faucet tx hash: 0x{}",
        hex::encode(faucet_tx_hash.as_bytes())
    );

    // Confirm and wait for indexer
    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync()
        .expect("Should sync indexer after faucet");

    // Step 2: Scan for Alice's cells
    println!("Step 2: Scanning for Alice's cells...");
    let scanner = Scanner::new(config.clone(), store.clone());
    let scan_results = scanner
        .scan_all_accounts(&[alice.clone()])
        .expect("Scan should succeed");

    assert_eq!(scan_results.len(), 1, "Should have 1 account result");
    let alice_result = &scan_results[0];

    println!("  Found {} cells", alice_result.cells.len());
    assert!(
        !alice_result.cells.is_empty(),
        "Alice should have at least 1 cell"
    );

    // Step 3: Verify cells have valid out_points
    println!("Step 3: Verifying out_point data...");
    for (i, cell) in alice_result.cells.iter().enumerate() {
        println!("  Cell {}: capacity = {} shannons", i, cell.capacity);
        println!("    out_point length = {} bytes", cell.out_point.len());

        // out_point should be 36 bytes: tx_hash (32) + index (4)
        assert_eq!(cell.out_point.len(), 36, "out_point should be 36 bytes");

        // Extract tx_hash and index
        let tx_hash = &cell.out_point[0..32];
        let index_bytes: [u8; 4] = cell.out_point[32..36].try_into().unwrap();
        let index = u32::from_le_bytes(index_bytes);

        println!("    tx_hash = 0x{}", hex::encode(tx_hash));
        println!("    index = {}", index);

        // CRITICAL CHECK: tx_hash should NOT be all zeros
        let is_zero_hash = tx_hash.iter().all(|&b| b == 0);
        assert!(
            !is_zero_hash,
            "tx_hash should NOT be all zeros! This indicates a bug in cell creation."
        );

        // The tx_hash should match our faucet transaction
        println!(
            "    Expected faucet tx: 0x{}",
            hex::encode(faucet_tx_hash.as_bytes())
        );
    }

    // Step 4: Load cells from store (as the wallet does)
    println!("Step 4: Loading cells from store...");
    let stored_cells = store
        .get_stealth_cells(alice.id)
        .expect("Should load cells");

    println!("  Loaded {} cells from store", stored_cells.len());
    assert!(!stored_cells.is_empty(), "Should have stored cells");

    // Verify stored cells also have valid out_points
    for (i, cell) in stored_cells.iter().enumerate() {
        let tx_hash = &cell.out_point[0..32];
        let is_zero_hash = tx_hash.iter().all(|&b| b == 0);
        assert!(
            !is_zero_hash,
            "Stored cell {} has zero tx_hash! This indicates a storage bug.",
            i
        );
    }

    // Step 5: Build and send transaction to Bob
    println!("Step 5: Building transaction from Alice to Bob...");
    let send_amount = 100_00000000u64; // 100 CKB

    // Build Bob's stealth address (66 bytes = view_pub || spend_pub)
    let bob_stealth_address = {
        let view_pub = bob.view_public_key().serialize();
        let spend_pub = bob.spend_public_key().serialize();
        [view_pub.as_slice(), spend_pub.as_slice()].concat()
    };

    let builder = StealthTxBuilder::new(config.clone());
    let builder = builder
        .add_output(bob_stealth_address, send_amount)
        .select_inputs(&stored_cells, send_amount)
        .expect("Input selection should succeed");

    // Debug: Print selected inputs
    println!("  Selected {} inputs:", builder.inputs.len());
    for (i, input) in builder.inputs.iter().enumerate() {
        let tx_hash = &input.out_point[0..32];
        let index_bytes: [u8; 4] = input.out_point[32..36].try_into().unwrap();
        let index = u32::from_le_bytes(index_bytes);
        println!(
            "    Input {}: tx_hash=0x{}, index={}",
            i,
            hex::encode(tx_hash),
            index
        );

        let is_zero_hash = tx_hash.iter().all(|&b| b == 0);
        assert!(!is_zero_hash, "Selected input {} has zero tx_hash!", i);
    }

    let built_tx = builder.build(&alice).expect("Building tx should succeed");
    println!(
        "  Built tx hash: 0x{}",
        hex::encode(built_tx.tx_hash.as_bytes())
    );

    // Sign the transaction
    let signed_tx = StealthTxBuilder::sign(
        built_tx,
        &alice,
        &alice.spend_secret_key_for_test(),
        &stored_cells,
    )
    .expect("Signing should succeed");

    // Submit the transaction
    use ckb_sdk::CkbRpcClient;
    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let send_tx_hash = client
        .send_transaction(signed_tx.clone(), None)
        .expect("Sending tx should succeed - if this fails with Invalid OutPoint, the bug exists");

    println!(
        "Step 6: Transaction sent successfully! Hash: 0x{}",
        hex::encode(send_tx_hash.as_bytes())
    );

    // Confirm
    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync()
        .expect("Should sync indexer after tx confirmation");

    // Step 7: Verify Bob received the funds
    println!("Step 7: Verifying Bob received funds...");
    let (bob_store, _bob_temp) = create_temp_store();
    let bob_scanner = Scanner::new(config.clone(), bob_store);
    let bob_scan = bob_scanner
        .full_scan(&bob)
        .expect("Bob scan should succeed");

    assert_eq!(bob_scan.stealth_cells.len(), 1, "Bob should have 1 cell");
    assert_eq!(
        bob_scan.total_capacity,
        send_amount,
        "Bob should have received {} CKB",
        send_amount / 100_000_000
    );

    println!(
        "  Bob received {} CKB - SUCCESS!",
        bob_scan.total_capacity / 100_000_000
    );
}

/// Test that cells from store have correct out_points after scan_all_accounts
#[test]
fn test_scan_stores_valid_outpoints() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    let alice = Account::new_random(0, "Alice".to_string());
    let stealth_code_hash = env.stealth_lock_code_hash();

    // Fund Alice
    let (eph_pub, stealth_pub) = obscell_wallet::domain::stealth::generate_ephemeral_key(
        &alice.view_public_key(),
        &alice.spend_public_key(),
    );
    let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
    let mut alice_args = Vec::with_capacity(53);
    alice_args.extend_from_slice(&eph_pub.serialize());
    alice_args.extend_from_slice(&pubkey_hash[0..20]);

    let faucet_tx_hash = env
        .faucet
        .transfer_to_stealth(&alice_args, &stealth_code_hash, 200_00000000u64)
        .expect("Faucet should succeed");

    println!("Faucet tx: 0x{}", hex::encode(faucet_tx_hash.as_bytes()));

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync");

    // Scan
    let scanner = Scanner::new(config, store.clone());
    let results = scanner
        .scan_all_accounts(&[alice.clone()])
        .expect("Scan should succeed");

    // Check cells in scan result
    println!(
        "Checking {} cells from scan result...",
        results[0].cells.len()
    );
    for cell in &results[0].cells {
        assert_eq!(cell.out_point.len(), 36);
        let tx_hash = &cell.out_point[0..32];
        let is_zero = tx_hash.iter().all(|&b| b == 0);
        println!(
            "  Scan result cell: tx_hash=0x{}, is_zero={}",
            hex::encode(tx_hash),
            is_zero
        );
        assert!(!is_zero, "Scan result cell has zero tx_hash!");
    }

    // Check cells loaded from store
    let stored_cells = store.get_stealth_cells(alice.id).expect("Should load");
    println!("Checking {} cells from store...", stored_cells.len());
    for cell in &stored_cells {
        assert_eq!(cell.out_point.len(), 36);
        let tx_hash = &cell.out_point[0..32];
        let is_zero = tx_hash.iter().all(|&b| b == 0);
        println!(
            "  Stored cell: tx_hash=0x{}, is_zero={}",
            hex::encode(tx_hash),
            is_zero
        );
        assert!(!is_zero, "Stored cell has zero tx_hash!");
    }

    println!("All cells have valid out_points!");
}
