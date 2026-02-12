//! Integration test for incremental scanning.
//!
//! This test reproduces the bug where cells received after the initial scan
//! don't appear until a full rescan is performed.

use tempfile::TempDir;

use super::devnet::DevNet;
use super::TestEnv;

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
        },
        contracts: ContractConfig {
            stealth_lock_code_hash: format!("0x{}", hex::encode(type_id_hash.as_bytes())),
            ct_token_code_hash: "0x".to_string() + &"0".repeat(64),
            ct_info_code_hash: "0x".to_string() + &"0".repeat(64),
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

/// Helper to fund an account via faucet
fn fund_account(env: &TestEnv, account: &Account, amount: u64) -> ckb_types::H256 {
    let stealth_code_hash = env.stealth_lock_code_hash();
    let (eph_pub, stealth_pub) = obscell_wallet::domain::stealth::generate_ephemeral_key(
        &account.view_public_key(),
        &account.spend_public_key(),
    );
    let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
    let mut args = Vec::with_capacity(53);
    args.extend_from_slice(&eph_pub.serialize());
    args.extend_from_slice(&pubkey_hash[0..20]);

    env.faucet
        .transfer_to_stealth(&args, &stealth_code_hash, amount)
        .expect("Faucet should succeed")
}

/// Test that incremental scan correctly detects new cells added after initial scan.
///
/// This test reproduces the bug:
/// 1. Create account, do initial full scan (no cells)
/// 2. Receive funds via faucet
/// 3. Incremental scan should find the new cell
/// 4. Receive more funds
/// 5. Incremental scan should find the second cell
#[test]
fn test_incremental_scan_finds_new_cells() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    let alice = Account::new_random(0, "Alice".to_string());

    // Step 1: Initial full scan (should find nothing)
    println!("Step 1: Initial full scan (expect 0 cells)...");
    let scanner = Scanner::new(config.clone(), store.clone());
    let initial_result = scanner
        .full_scan_all(&[alice.clone()])
        .expect("Full scan should succeed");

    assert_eq!(
        initial_result.stealth_results[0].cells.len(),
        0,
        "Should have no cells initially"
    );
    println!(
        "  Found {} cells (expected 0)",
        initial_result.stealth_results[0].cells.len()
    );

    // Check what cursor was saved
    let cursor_after_initial = scanner.load_cursor().expect("Should load cursor");
    println!(
        "  Cursor after initial scan: {}",
        cursor_after_initial
            .as_ref()
            .map(|c| format!(
                "0x{}...",
                hex::encode(&c.as_bytes()[..8.min(c.as_bytes().len())])
            ))
            .unwrap_or_else(|| "None".to_string())
    );

    // Step 2: Fund Alice via faucet
    println!("\nStep 2: Funding Alice via faucet...");
    let faucet_tx_hash = fund_account(env, &alice, 200_00000000u64);
    println!("  Faucet tx: 0x{}", hex::encode(faucet_tx_hash.as_bytes()));

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync indexer");

    // Step 3: Incremental scan (should find the new cell)
    println!("\nStep 3: Incremental scan (expect 1 cell)...");
    let incremental_result = scanner
        .incremental_scan(&[alice.clone()])
        .expect("Incremental scan should succeed");

    let cells_found = incremental_result.stealth_results[0].cells.len();
    let new_cells_found = incremental_result.stealth_results[0].new_cells.len();
    println!(
        "  Found {} cells total, {} new cells",
        cells_found, new_cells_found
    );

    // THIS IS THE BUG: If incremental scan doesn't find the new cell, we have a problem
    if cells_found == 0 {
        println!("  BUG DETECTED: Incremental scan didn't find the new cell!");
        println!("  This confirms the bug where new cells are not detected by incremental scan.");

        // Let's also check what a full scan would find
        println!("\n  Verifying with full scan...");
        let full_result = scanner
            .full_scan_all(&[alice.clone()])
            .expect("Full scan should succeed");
        println!(
            "  Full scan found {} cells",
            full_result.stealth_results[0].cells.len()
        );
    }

    assert_eq!(
        cells_found, 1,
        "Incremental scan should find the new cell from faucet"
    );

    // Step 4: Fund Alice again
    println!("\nStep 4: Funding Alice again via faucet...");
    let faucet_tx_hash2 = fund_account(env, &alice, 300_00000000u64);
    println!("  Faucet tx: 0x{}", hex::encode(faucet_tx_hash2.as_bytes()));

    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync indexer");

    // Step 5: Second incremental scan
    println!("\nStep 5: Second incremental scan (expect 2 cells total, 1 new)...");
    let incremental_result2 = scanner
        .incremental_scan(&[alice.clone()])
        .expect("Second incremental scan should succeed");

    let cells_found2 = incremental_result2.stealth_results[0].cells.len();
    let new_cells_found2 = incremental_result2.stealth_results[0].new_cells.len();
    println!(
        "  Found {} cells total, {} new cells",
        cells_found2, new_cells_found2
    );

    // Load from store to verify
    let stored_cells = store
        .get_stealth_cells(alice.id)
        .expect("Should load cells");
    println!("  Store has {} cells", stored_cells.len());

    assert_eq!(
        stored_cells.len(),
        2,
        "Store should have 2 cells after two faucet transactions"
    );

    println!("\nTest passed! Incremental scan correctly finds new cells.");
}

/// Test that simulates the exact user flow:
/// 1. Create wallet and account (first scan happens)
/// 2. Use faucet multiple times
/// 3. Auto-scan (incremental) should detect new cells
#[test]
fn test_auto_scan_detects_faucet_cells() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    let alice = Account::new_random(0, "Alice".to_string());
    let scanner = Scanner::new(config.clone(), store.clone());

    // Simulate what happens when user creates account:
    // The app does a full scan to initialize
    println!("Simulating account creation: full scan...");
    let _ = scanner
        .full_scan_all(&[alice.clone()])
        .expect("Full scan should succeed");

    // User clicks faucet button twice
    println!("User uses faucet twice...");
    let _ = fund_account(env, &alice, 100_00000000u64);
    env.generate_blocks(5).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync indexer"); // Wait before second faucet

    let _ = fund_account(env, &alice, 100_00000000u64);
    env.generate_blocks(5).expect("Should generate blocks");
    env.wait_for_indexer_sync().expect("Should sync indexer");

    // Auto-scan kicks in (incremental)
    println!("Auto-scan (incremental) kicks in...");
    let result = scanner
        .incremental_scan(&[alice.clone()])
        .expect("Incremental scan should succeed");

    let cells_found = result.stealth_results[0].cells.len();
    println!("Auto-scan found {} cells (expected 2)", cells_found);

    // Check store
    let stored_cells = store
        .get_stealth_cells(alice.id)
        .expect("Should load cells");
    println!("Store has {} cells (expected 2)", stored_cells.len());

    // Calculate total balance
    let total_balance: u64 = stored_cells.iter().map(|c| c.capacity).sum();
    println!(
        "Total balance: {} CKB (expected 200)",
        total_balance / 100_000_000
    );

    assert_eq!(
        cells_found, 2,
        "Incremental scan should find both faucet cells"
    );
    assert_eq!(stored_cells.len(), 2, "Store should have both cells");
    assert_eq!(
        total_balance, 200_00000000u64,
        "Total balance should be 200 CKB"
    );
}
