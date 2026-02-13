//! Integration test for faucet -> stealth lock transaction history.
//!
//! Tests that receiving CKB from a non-stealth lock (faucet) properly
//! records transaction history for the recipient.

use tempfile::TempDir;

use super::devnet::DevNet;
use super::TestEnv;

use obscell_wallet::config::{
    CellDepConfig, CellDepsConfig, Config, ContractConfig, NetworkConfig,
};
use obscell_wallet::domain::account::Account;
use obscell_wallet::domain::cell::TxType;
use obscell_wallet::domain::stealth::generate_ephemeral_key;
#[allow(unused_imports)]
use obscell_wallet::infra::block_scanner::BlockScanner;
use obscell_wallet::infra::scanner::Scanner;
use obscell_wallet::infra::store::Store;

/// Create a test config pointing to the devnet with deployed contracts.
fn create_test_config(env: &TestEnv) -> Config {
    let (stealth_lock_tx_hash, stealth_lock_index) = env.stealth_lock_cell_dep();
    let stealth_type_id_hash = env.stealth_lock_code_hash();
    let (ckb_auth_tx_hash, ckb_auth_index) = env.ckb_auth_cell_dep();
    let ckb_auth_data_hash = env.ckb_auth_data_hash();

    Config {
        network: NetworkConfig {
            name: "devnet".to_string(),
            rpc_url: DevNet::RPC_URL.to_string(),
            scan_start_block: 0,
        },
        contracts: ContractConfig {
            stealth_lock_code_hash: format!("0x{}", hex::encode(stealth_type_id_hash.as_bytes())),
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

/// Test that receiving CKB from faucet (non-stealth lock) records transaction history.
///
/// This test verifies that when a stealth lock address receives CKB from a
/// non-stealth lock sender (like the faucet), the transaction is properly
/// recorded in the recipient's transaction history.
#[test]
fn test_faucet_to_stealth_records_history() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create Alice's account
    let alice = Account::new_random(0, "Alice".to_string());
    let stealth_code_hash = env.stealth_lock_code_hash();

    // Step 1: Generate stealth address for Alice
    println!("Step 1: Generating stealth address for Alice...");
    let (eph_pub, stealth_pub) =
        generate_ephemeral_key(&alice.view_public_key(), &alice.spend_public_key());
    let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
    let mut lock_args = Vec::with_capacity(53);
    lock_args.extend_from_slice(&eph_pub.serialize());
    lock_args.extend_from_slice(&pubkey_hash[0..20]);

    // Step 2: Send CKB from faucet (non-stealth lock) to Alice's stealth address
    println!("Step 2: Sending CKB from faucet to Alice's stealth address...");
    let faucet_amount = 200_00000000u64; // 200 CKB
    let faucet_tx_hash = env
        .faucet
        .transfer_to_stealth(&lock_args, &stealth_code_hash, faucet_amount)
        .expect("Faucet transfer should succeed");

    println!(
        "  Faucet tx hash: 0x{}",
        hex::encode(faucet_tx_hash.as_bytes())
    );

    // Confirm the transaction
    env.generate_blocks(10).expect("Should generate blocks");
    env.wait_for_indexer_sync()
        .expect("Should sync indexer after faucet");

    // Step 3: Scan cells using indexer-based Scanner
    println!("Step 3: Scanning for Alice's cells...");
    let scanner = Scanner::new(config.clone(), store.clone());
    let scan_results = scanner
        .scan_all_accounts(&[alice.clone()])
        .expect("Cell scan should succeed");

    println!("  Found {} cells for Alice", scan_results[0].cells.len());
    assert!(
        !scan_results[0].cells.is_empty(),
        "Alice should have at least 1 stealth cell"
    );

    // Step 4: Scan transaction history
    println!("Step 4: Scanning transaction history...");
    scanner
        .scan_tx_history(&alice)
        .expect("History scan should succeed");

    // Step 5: Check transaction history
    println!("Step 5: Checking Alice's transaction history...");
    let alice_history = store
        .get_tx_history(alice.id)
        .expect("Should load Alice's history");

    println!("  Alice has {} history entries", alice_history.len());

    // THE BUG: If history is empty, the bug exists
    assert!(
        !alice_history.is_empty(),
        "BUG: Alice should have transaction history for receiving from faucet, but history is empty!"
    );

    // Verify the history entry is a CKB receive with positive delta
    let faucet_receive = alice_history.iter().find(|record| {
        if let TxType::Ckb { delta } = &record.tx_type {
            *delta > 0
        } else {
            false
        }
    });

    assert!(
        faucet_receive.is_some(),
        "Alice should have a CKB receive (positive delta) entry in history"
    );

    let record = faucet_receive.unwrap();
    println!(
        "  History entry found: delta = {} CKB (raw: {} shannon)",
        record.delta_ckb().unwrap(),
        if let TxType::Ckb { delta } = &record.tx_type {
            *delta
        } else {
            0
        }
    );
    println!(
        "  Expected: {} CKB (raw: {} shannon)",
        faucet_amount as f64 / 100_000_000.0,
        faucet_amount
    );
    println!("  Record tx_hash: 0x{}", hex::encode(&record.tx_hash));

    // Verify the delta matches the faucet amount
    if let TxType::Ckb { delta } = &record.tx_type {
        assert_eq!(
            *delta as u64, faucet_amount,
            "History delta should match faucet amount"
        );
    }

    // Verify tx_hash matches
    assert_eq!(
        record.tx_hash,
        faucet_tx_hash.as_bytes(),
        "History tx_hash should match faucet tx_hash"
    );

    println!("\nTest passed: Faucet -> stealth lock transaction properly recorded in history!");
}

/// Test that receiving CKB from faucet records transaction history using BlockScanner.
///
/// This test uses BlockScanner (the same scanner used in TUI) instead of
/// the indexer-based Scanner, to verify the bug report about faucet->stealth
/// transactions not appearing in history.
///
/// NOTE: This test is ignored because BlockScanner uses BlockV1 format (CKB2023+)
/// which is not supported by the devnet's CKB version. The devnet returns Block
/// with 4 fields instead of BlockV1 with 5 fields.
/// To test BlockScanner, use testnet or mainnet.
#[test]
#[ignore = "BlockScanner requires BlockV1 format not available on devnet"]
fn test_faucet_to_stealth_records_history_block_scanner() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    let (store, _temp_dir) = create_temp_store();

    // Create Alice's account
    let alice = Account::new_random(0, "Alice".to_string());
    let stealth_code_hash = env.stealth_lock_code_hash();

    // Step 1: Generate stealth address for Alice
    println!("Step 1: Generating stealth address for Alice...");
    let (eph_pub, stealth_pub) =
        generate_ephemeral_key(&alice.view_public_key(), &alice.spend_public_key());
    let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
    let mut lock_args = Vec::with_capacity(53);
    lock_args.extend_from_slice(&eph_pub.serialize());
    lock_args.extend_from_slice(&pubkey_hash[0..20]);

    // Step 2: Send CKB from faucet (non-stealth lock) to Alice's stealth address
    println!("Step 2: Sending CKB from faucet to Alice's stealth address...");
    let faucet_amount = 200_00000000u64; // 200 CKB
    let faucet_tx_hash = env
        .faucet
        .transfer_to_stealth(&lock_args, &stealth_code_hash, faucet_amount)
        .expect("Faucet transfer should succeed");

    println!(
        "  Faucet tx hash: 0x{}",
        hex::encode(faucet_tx_hash.as_bytes())
    );

    // Confirm the transaction
    env.generate_blocks(10).expect("Should generate blocks");

    // Step 3: Scan blocks using BlockScanner (same as TUI uses)
    println!("Step 3: Scanning blocks with BlockScanner...");
    let block_scanner = BlockScanner::new(config.clone(), store.clone());

    // Scan from block 0 to find Alice's cells and record history
    let blocks_scanned = block_scanner
        .scan_blocks(&[alice.clone()], None)
        .expect("Block scan should succeed");
    println!("  Scanned {} blocks", blocks_scanned);

    // Step 4: Check Alice's cells were found
    let alice_cells = store
        .get_stealth_cells(alice.id)
        .expect("Should load Alice's cells");
    println!("  Found {} stealth cells for Alice", alice_cells.len());
    assert!(
        !alice_cells.is_empty(),
        "Alice should have at least 1 stealth cell"
    );

    // Step 5: Check transaction history
    println!("Step 5: Checking Alice's transaction history...");
    let alice_history = store
        .get_tx_history(alice.id)
        .expect("Should load Alice's history");

    println!("  Alice has {} history entries", alice_history.len());

    // THE BUG: If history is empty, the bug exists in BlockScanner
    assert!(
        !alice_history.is_empty(),
        "BUG: BlockScanner should record transaction history for faucet->stealth, but history is empty!"
    );

    // Verify the history entry is a CKB receive with positive delta
    let faucet_receive = alice_history.iter().find(|record| {
        if let TxType::Ckb { delta } = &record.tx_type {
            *delta > 0
        } else {
            false
        }
    });

    assert!(
        faucet_receive.is_some(),
        "Alice should have a CKB receive (positive delta) entry in history"
    );

    let record = faucet_receive.unwrap();
    println!(
        "  History entry found: delta = {} CKB (raw: {} shannon)",
        record.delta_ckb().unwrap(),
        if let TxType::Ckb { delta } = &record.tx_type {
            *delta
        } else {
            0
        }
    );

    // Verify the delta matches the faucet amount
    if let TxType::Ckb { delta } = &record.tx_type {
        assert_eq!(
            *delta as u64, faucet_amount,
            "History delta should match faucet amount"
        );
    }

    // Verify tx_hash matches
    assert_eq!(
        record.tx_hash,
        faucet_tx_hash.as_bytes(),
        "History tx_hash should match faucet tx_hash"
    );

    println!("\nTest passed: BlockScanner properly records faucet->stealth history!");
}
