//! Integration test for faucet -> stealth lock transaction history.
//!
//! Tests that receiving CKB from a non-stealth lock (faucet) properly
//! records transaction history for the recipient.

use ckb_sdk::CkbRpcClient;
use tempfile::TempDir;

use super::TestEnv;
use super::devnet::DevNet;

use obscell_wallet::config::{
    CellDepConfig, CellDepsConfig, Config, ContractConfig, NetworkConfig,
};
use obscell_wallet::domain::account::Account;
use obscell_wallet::domain::cell::TxType;
use obscell_wallet::domain::stealth::generate_ephemeral_key;
use obscell_wallet::domain::tx_builder::StealthTxBuilder;
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
            scan_start_block: 1, // Block 0 doesn't support BlockV1 format
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
#[test]
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

/// Test that BlockScanner correctly calculates delta for sender (Alice -> Bob transfer).
///
/// This test verifies that when Alice sends CKB to Bob:
/// 1. Alice's history shows a SEND (negative delta)
/// 2. Bob's history shows a RECEIVE (positive delta)
/// 3. The deltas are calculated correctly based on inputs/outputs
///
/// This is a regression test for the bug where sender's history showed "receive"
/// instead of "send" when input cells were not found in the store.
#[test]
fn test_block_scanner_send_delta_calculation() {
    let env = TestEnv::get();
    let config = create_test_config(env);
    // Use a single shared store for both accounts (simulating same wallet)
    let (store, _temp_dir) = create_temp_store();

    // Create Alice and Bob accounts
    let alice = Account::new_random(0, "Alice".to_string());
    let bob = Account::new_random(1, "Bob".to_string());
    let stealth_code_hash = env.stealth_lock_code_hash();

    println!("=== Test: BlockScanner send delta calculation ===\n");

    // Step 1: Fund Alice with CKB from faucet
    println!("Step 1: Funding Alice with 500 CKB from faucet...");
    let initial_amount = 500_00000000u64; // 500 CKB

    let (alice_eph_pub, alice_stealth_pub) =
        generate_ephemeral_key(&alice.view_public_key(), &alice.spend_public_key());
    let alice_pubkey_hash = ckb_hash::blake2b_256(alice_stealth_pub.serialize());
    let mut alice_lock_args = Vec::with_capacity(53);
    alice_lock_args.extend_from_slice(&alice_eph_pub.serialize());
    alice_lock_args.extend_from_slice(&alice_pubkey_hash[0..20]);

    let faucet_tx_hash = env
        .faucet
        .transfer_to_stealth(&alice_lock_args, &stealth_code_hash, initial_amount)
        .expect("Faucet transfer to Alice should succeed");

    println!("  Faucet tx: 0x{}", hex::encode(faucet_tx_hash.as_bytes()));

    // Confirm the transaction
    env.generate_blocks(10).expect("Should generate blocks");

    // Step 2: Scan blocks to find Alice's cell and record receive history
    println!("Step 2: Scanning blocks to find Alice's funded cell...");
    let block_scanner = BlockScanner::new(config.clone(), store.clone());
    block_scanner
        .scan_blocks(&[alice.clone(), bob.clone()], None)
        .expect("Block scan should succeed");

    // Verify Alice has her funded cell in the store
    let alice_cells = store
        .get_stealth_cells(alice.id)
        .expect("Should get Alice's cells");
    println!("  Alice has {} stealth cell(s)", alice_cells.len());
    assert_eq!(
        alice_cells.len(),
        1,
        "Alice should have exactly 1 cell after faucet funding"
    );
    assert_eq!(
        alice_cells[0].capacity, initial_amount,
        "Alice's cell should have 500 CKB"
    );

    // Verify Alice's history shows receive
    let alice_history_after_fund = store
        .get_tx_history(alice.id)
        .expect("Should get Alice's history");
    println!(
        "  Alice has {} history entry(ies) after funding",
        alice_history_after_fund.len()
    );
    assert_eq!(
        alice_history_after_fund.len(),
        1,
        "Alice should have 1 history entry after funding"
    );

    if let TxType::Ckb { delta } = &alice_history_after_fund[0].tx_type {
        assert!(
            *delta > 0,
            "Alice's first history entry should be receive (positive delta)"
        );
        println!("  Alice received: {} CKB", *delta as f64 / 100_000_000.0);
    } else {
        panic!("Expected CKB type in history");
    }

    // Step 3: Alice sends 100 CKB to Bob
    println!("\nStep 3: Alice sends 100 CKB to Bob...");
    let send_amount = 100_00000000u64; // 100 CKB

    // Build Bob's stealth address
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

    // Send the transaction
    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let send_tx_hash = client
        .send_transaction(signed_tx, None)
        .expect("Sending tx should succeed");

    println!("  Send tx: 0x{}", hex::encode(send_tx_hash.as_bytes()));

    // Confirm the transaction
    env.generate_blocks(10).expect("Should generate blocks");

    // Step 4: Scan blocks again to process the send transaction
    println!("\nStep 4: Scanning blocks to process the send transaction...");
    block_scanner
        .scan_blocks(&[alice.clone(), bob.clone()], None)
        .expect("Block scan should succeed");

    // Step 5: Verify Alice's history shows SEND (negative delta)
    println!("\nStep 5: Verifying Alice's history...");
    let alice_history_final = store
        .get_tx_history(alice.id)
        .expect("Should get Alice's final history");

    println!(
        "  Alice has {} history entry(ies)",
        alice_history_final.len()
    );
    assert_eq!(
        alice_history_final.len(),
        2,
        "Alice should have 2 history entries (receive + send)"
    );

    // Find the send entry (negative delta)
    let alice_send_entry = alice_history_final
        .iter()
        .find(|h| matches!(&h.tx_type, TxType::Ckb { delta } if *delta < 0));

    assert!(
        alice_send_entry.is_some(),
        "BUG: Alice should have a SEND entry (negative delta) in history, but none found! \
         This indicates BlockScanner failed to correctly calculate delta for the sender."
    );

    let send_record = alice_send_entry.unwrap();
    if let TxType::Ckb { delta } = &send_record.tx_type {
        // Alice sent 100 CKB, plus some fee, so delta should be around -100 CKB
        // The actual delta = change_output - input = (500 - 100 - fee) - 500 = -(100 + fee)
        println!(
            "  Alice's send delta: {} CKB",
            *delta as f64 / 100_000_000.0
        );
        assert!(*delta < 0, "Send delta should be negative");
        // The delta should be at least -100 CKB (send amount), possibly more due to fees
        assert!(
            *delta <= -(send_amount as i64),
            "Send delta should be at least -{} (sent amount), but got {}",
            send_amount,
            delta
        );
    }

    // Verify the tx_hash matches
    assert_eq!(
        send_record.tx_hash,
        send_tx_hash.as_bytes(),
        "Send record tx_hash should match"
    );

    // Step 6: Verify Bob's history shows RECEIVE (positive delta)
    println!("\nStep 6: Verifying Bob's history...");
    let bob_history = store
        .get_tx_history(bob.id)
        .expect("Should get Bob's history");

    println!("  Bob has {} history entry(ies)", bob_history.len());
    assert_eq!(
        bob_history.len(),
        1,
        "Bob should have 1 history entry (receive)"
    );

    if let TxType::Ckb { delta } = &bob_history[0].tx_type {
        assert_eq!(
            *delta,
            send_amount as i64,
            "Bob should receive exactly {} CKB",
            send_amount as f64 / 100_000_000.0
        );
        println!("  Bob received: {} CKB", *delta as f64 / 100_000_000.0);
    } else {
        panic!("Bob's history should be CKB type");
    }

    // Verify Bob's cell
    let bob_cells = store
        .get_stealth_cells(bob.id)
        .expect("Should get Bob's cells");
    assert_eq!(bob_cells.len(), 1, "Bob should have 1 cell");
    assert_eq!(
        bob_cells[0].capacity, send_amount,
        "Bob's cell should have 100 CKB"
    );

    println!("\n=== Test passed: BlockScanner correctly calculates send delta! ===");
    println!("  Alice: funded 500 CKB, sent ~100 CKB, history shows correct SEND");
    println!("  Bob: received 100 CKB, history shows correct RECEIVE");
}
