//! End-to-end basic flow integration test.
//!
//! Tests the basic stealth flow:
//! 1. Create test accounts
//! 2. Fund accounts via faucet
//! 3. Create stealth lock cells
//! 4. Verify cells can be found via scanning

use ckb_hash::blake2b_256;
use ckb_sdk::CkbRpcClient;
use ckb_sdk::rpc::ckb_indexer::{Order, ScriptType, SearchKey, SearchMode};
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use super::devnet::DevNet;
use super::{TestEnv, contract_deployer::SIGHASH_ALL_CODE_HASH};

/// Generate stealth script args for a one-time address.
///
/// Returns (stealth_script_args, stealth_secret_key) where:
/// - stealth_script_args is 53 bytes: eph_pub (33) || pubkey_hash[0..20] (20)
/// - stealth_secret_key can sign for this address
fn generate_stealth_args(
    view_pub: &PublicKey,
    spend_pub: &PublicKey,
    spend_secret: &SecretKey,
    _view_secret: &SecretKey,
) -> (Vec<u8>, SecretKey) {
    use secp256k1::ecdh::SharedSecret;
    use sha2::{Digest, Sha256};

    let secp = Secp256k1::new();
    let mut rng = OsRng;

    loop {
        // Generate ephemeral key
        let eph_secret = SecretKey::new(&mut rng);
        let eph_pub = PublicKey::from_secret_key(&secp, &eph_secret);

        // ECDH: shared = eph_secret * view_pub
        let shared = SharedSecret::new(view_pub, &eph_secret);

        // Hash shared secret
        let mut hasher = Sha256::new();
        hasher.update(shared.secret_bytes());
        let hash = hasher.finalize();

        if let Ok(hashed_key) = SecretKey::from_slice(&hash) {
            // Derive stealth pubkey: stealth_pub = spend_pub + H(shared)*G
            let tweaked_pub = PublicKey::from_secret_key(&secp, &hashed_key);
            let stealth_pub = spend_pub.combine(&tweaked_pub).expect("combine ok");

            // Derive stealth secret: stealth_secret = spend_secret + H(shared)
            let scalar = secp256k1::Scalar::from_be_bytes(hashed_key.secret_bytes()).unwrap();
            let stealth_secret = spend_secret.add_tweak(&scalar).unwrap();

            // Build script args: eph_pub (33) || blake2b(stealth_pub)[0..20] (20)
            let pubkey_hash = blake2b_256(stealth_pub.serialize());
            let mut script_args = Vec::with_capacity(53);
            script_args.extend_from_slice(&eph_pub.serialize());
            script_args.extend_from_slice(&pubkey_hash[0..20]);

            return (script_args, stealth_secret);
        }
    }
}

/// Verify that a stealth script args matches the expected keys.
fn verify_stealth_ownership(
    stealth_script_args: &[u8],
    view_secret: &SecretKey,
    spend_pub: &PublicKey,
) -> bool {
    use secp256k1::ecdh::SharedSecret;
    use sha2::{Digest, Sha256};

    if stealth_script_args.len() != 53 {
        return false;
    }

    // Parse ephemeral pubkey
    let eph_pub = match PublicKey::from_slice(&stealth_script_args[0..33]) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // ECDH: shared = view_secret * eph_pub
    let shared = SharedSecret::new(&eph_pub, view_secret);

    // Hash shared secret
    let mut hasher = Sha256::new();
    hasher.update(shared.secret_bytes());
    let hash = hasher.finalize();

    if let Ok(hashed_key) = SecretKey::from_slice(&hash) {
        // Derive expected stealth pubkey
        let tweaked_pub = PublicKey::from_secret_key_global(&hashed_key);
        if let Ok(stealth_pub) = spend_pub.combine(&tweaked_pub) {
            // Check pubkey hash matches
            let pubkey_hash = blake2b_256(stealth_pub.serialize());
            return pubkey_hash[0..20] == stealth_script_args[33..53];
        }
    }

    false
}

#[test]
fn test_env_setup() {
    let env = TestEnv::get();

    // Verify devnet is running
    assert!(env.devnet.is_running(), "DevNet should be running");

    // Verify contracts are deployed
    let stealth_lock = &env.contracts.stealth_lock;
    assert!(
        stealth_lock.type_id_hash.is_some(),
        "Stealth-lock contract should have type_id_hash"
    );

    let ckb_auth = &env.contracts.ckb_auth;
    assert!(
        ckb_auth.data_hash.as_bytes().iter().any(|&b| b != 0),
        "CKB-auth contract should have data_hash"
    );

    println!("Test environment verified:");
    println!(
        "  - Stealth-lock tx_hash: 0x{}",
        hex::encode(stealth_lock.tx_hash.as_bytes())
    );
    println!(
        "  - Stealth-lock type_id_hash: 0x{}",
        hex::encode(stealth_lock.type_id_hash.as_ref().unwrap().as_bytes())
    );
    println!(
        "  - CKB-auth tx_hash: 0x{}",
        hex::encode(ckb_auth.tx_hash.as_bytes())
    );
    println!(
        "  - CKB-auth data_hash: 0x{}",
        hex::encode(ckb_auth.data_hash.as_bytes())
    );
    println!("  - Checkpoint: block {}", env.checkpoint);
}

#[test]
fn test_faucet_transfer() {
    let env = TestEnv::get();

    // Generate a random recipient
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let recipient_secret = SecretKey::new(&mut rng);
    let recipient_pub = PublicKey::from_secret_key(&secp, &recipient_secret);
    let recipient_lock_args = {
        let hash = blake2b_256(recipient_pub.serialize());
        let mut args = [0u8; 20];
        args.copy_from_slice(&hash[0..20]);
        args
    };

    println!(
        "Recipient lock args: 0x{}",
        hex::encode(recipient_lock_args)
    );

    // Transfer 100 CKB
    let amount = 100_00000000u64; // 100 CKB
    let tx_hash = env
        .faucet
        .transfer(&recipient_lock_args, amount)
        .expect("Faucet transfer should succeed");

    println!("Transfer tx: 0x{}", hex::encode(tx_hash.as_bytes()));

    // Generate blocks to confirm - CKB requires transaction to be proposed first,
    // then committed after the proposal window. We need multiple blocks.
    env.generate_blocks(10).expect("Should generate blocks");

    // Wait for indexer to sync
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Verify recipient received the CKB
    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let recipient_lock = ckb_jsonrpc_types::Script {
        code_hash: ckb_types::H256::from_slice(&hex::decode(SIGHASH_ALL_CODE_HASH).unwrap())
            .unwrap(),
        hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
        args: ckb_jsonrpc_types::JsonBytes::from_vec(recipient_lock_args.to_vec()),
    };

    let search_key = SearchKey {
        script: recipient_lock,
        script_type: ScriptType::Lock,
        script_search_mode: Some(SearchMode::Exact),
        filter: None,
        with_data: Some(false),
        group_by_transaction: None,
    };

    let result = client
        .get_cells(search_key, Order::Asc, 10.into(), None)
        .expect("Should get cells");

    assert!(!result.objects.is_empty(), "Recipient should have cells");

    let total: u64 = result
        .objects
        .iter()
        .map(|c| -> u64 { c.output.capacity.into() })
        .sum();
    assert_eq!(
        total, amount,
        "Recipient should have exactly {} CKB",
        amount
    );

    println!(
        "Faucet transfer verified: {} CKB received",
        amount / 100_000_000
    );

    // Note: Not resetting - tests should be independent of chain state
}

#[test]
fn test_stealth_cell_creation() {
    let env = TestEnv::get();

    // Generate stealth address keys (simulating an account)
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    let view_secret = SecretKey::new(&mut rng);
    let spend_secret = SecretKey::new(&mut rng);
    let view_pub = PublicKey::from_secret_key(&secp, &view_secret);
    let spend_pub = PublicKey::from_secret_key(&secp, &spend_secret);

    // Generate stealth script args
    let (stealth_args, _stealth_secret) =
        generate_stealth_args(&view_pub, &spend_pub, &spend_secret, &view_secret);

    println!("Stealth args: 0x{}", hex::encode(&stealth_args));
    println!("Stealth args length: {} bytes", stealth_args.len());

    // Verify ownership locally
    assert!(
        verify_stealth_ownership(&stealth_args, &view_secret, &spend_pub),
        "Stealth ownership verification should succeed"
    );

    // Transfer to stealth address
    let amount = 100_00000000u64; // 100 CKB
    let stealth_code_hash = env.stealth_lock_code_hash();

    let tx_hash = env
        .faucet
        .transfer_to_stealth(&stealth_args, &stealth_code_hash, amount)
        .expect("Stealth transfer should succeed");

    println!("Stealth transfer tx: 0x{}", hex::encode(tx_hash.as_bytes()));

    // Generate blocks to confirm - need multiple for proposal window
    env.generate_blocks(10).expect("Should generate blocks");

    // Wait for indexer to sync
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Verify stealth cell exists by searching for cells with our stealth lock
    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let stealth_lock = ckb_jsonrpc_types::Script {
        code_hash: stealth_code_hash,
        hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
        args: ckb_jsonrpc_types::JsonBytes::from_vec(stealth_args.clone()),
    };

    let search_key = SearchKey {
        script: stealth_lock,
        script_type: ScriptType::Lock,
        script_search_mode: Some(SearchMode::Exact),
        filter: None,
        with_data: Some(false),
        group_by_transaction: None,
    };

    let result = client
        .get_cells(search_key, Order::Asc, 10.into(), None)
        .expect("Should get cells");

    assert!(
        !result.objects.is_empty(),
        "Stealth cell should exist on chain"
    );

    let cell = &result.objects[0];
    let capacity: u64 = cell.output.capacity.into();
    assert_eq!(
        capacity, amount,
        "Stealth cell should have correct capacity"
    );

    println!(
        "Stealth cell verified: {} CKB at 0x{}:{}",
        capacity / 100_000_000,
        hex::encode(cell.out_point.tx_hash.as_bytes()),
        cell.out_point.index.value()
    );

    // Note: Not resetting - tests should be independent of chain state
}

#[test]
fn test_stealth_cell_scanning() {
    let env = TestEnv::get();

    // Generate two accounts
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    // Account 1 (Alice)
    let alice_view_secret = SecretKey::new(&mut rng);
    let alice_spend_secret = SecretKey::new(&mut rng);
    let alice_view_pub = PublicKey::from_secret_key(&secp, &alice_view_secret);
    let alice_spend_pub = PublicKey::from_secret_key(&secp, &alice_spend_secret);

    // Account 2 (Bob)
    let bob_view_secret = SecretKey::new(&mut rng);
    let bob_spend_secret = SecretKey::new(&mut rng);
    let bob_view_pub = PublicKey::from_secret_key(&secp, &bob_view_secret);
    let bob_spend_pub = PublicKey::from_secret_key(&secp, &bob_spend_secret);

    // Create stealth cells for Alice and Bob
    let (alice_stealth_args, _) = generate_stealth_args(
        &alice_view_pub,
        &alice_spend_pub,
        &alice_spend_secret,
        &alice_view_secret,
    );
    let (bob_stealth_args, _) = generate_stealth_args(
        &bob_view_pub,
        &bob_spend_pub,
        &bob_spend_secret,
        &bob_view_secret,
    );

    let stealth_code_hash = env.stealth_lock_code_hash();

    // Send 100 CKB to Alice
    let alice_amount = 100_00000000u64;
    env.faucet
        .transfer_to_stealth(&alice_stealth_args, &stealth_code_hash, alice_amount)
        .expect("Alice transfer should succeed");

    // Generate blocks to confirm Alice's transfer before sending Bob's
    env.generate_blocks(5).expect("Should generate blocks");

    // Send 200 CKB to Bob
    let bob_amount = 200_00000000u64;
    env.faucet
        .transfer_to_stealth(&bob_stealth_args, &stealth_code_hash, bob_amount)
        .expect("Bob transfer should succeed");

    // Generate blocks to confirm Bob's transfer
    env.generate_blocks(10).expect("Should generate blocks");

    // Wait for indexer to sync
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Scan all stealth cells
    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let prefix_lock = ckb_jsonrpc_types::Script {
        code_hash: stealth_code_hash.clone(),
        hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
        args: ckb_jsonrpc_types::JsonBytes::default(), // Empty for prefix search
    };

    let search_key = SearchKey {
        script: prefix_lock,
        script_type: ScriptType::Lock,
        script_search_mode: Some(SearchMode::Prefix),
        filter: None,
        with_data: Some(false),
        group_by_transaction: None,
    };

    let result = client
        .get_cells(search_key, Order::Asc, 100.into(), None)
        .expect("Should get cells");

    println!("Found {} stealth cells on chain", result.objects.len());

    // Verify Alice can find her cell
    let mut alice_found = 0u64;
    let mut bob_found = 0u64;

    for cell in &result.objects {
        let lock_args = cell.output.lock.args.as_bytes();
        let capacity: u64 = cell.output.capacity.into();

        if verify_stealth_ownership(lock_args, &alice_view_secret, &alice_spend_pub) {
            alice_found += capacity;
            println!("Alice found cell: {} CKB", capacity / 100_000_000);
        }

        if verify_stealth_ownership(lock_args, &bob_view_secret, &bob_spend_pub) {
            bob_found += capacity;
            println!("Bob found cell: {} CKB", capacity / 100_000_000);
        }
    }

    assert_eq!(alice_found, alice_amount, "Alice should find 100 CKB");
    assert_eq!(bob_found, bob_amount, "Bob should find 200 CKB");

    // Verify cells are not visible to wrong keys
    let wrong_secret = SecretKey::new(&mut rng);
    let wrong_pub = PublicKey::from_secret_key(&secp, &wrong_secret);

    for cell in &result.objects {
        let lock_args = cell.output.lock.args.as_bytes();
        assert!(
            !verify_stealth_ownership(lock_args, &wrong_secret, &wrong_pub),
            "Wrong keys should not match any cell"
        );
    }

    println!(
        "Stealth scanning verified: Alice={} CKB, Bob={} CKB",
        alice_found / 100_000_000,
        bob_found / 100_000_000
    );

    // Note: Not resetting - tests should be independent of chain state
}

#[test]
fn test_multiple_stealth_cells_same_account() {
    let env = TestEnv::get();

    // Generate account
    let secp = Secp256k1::new();
    let mut rng = OsRng;

    let view_secret = SecretKey::new(&mut rng);
    let spend_secret = SecretKey::new(&mut rng);
    let view_pub = PublicKey::from_secret_key(&secp, &view_secret);
    let spend_pub = PublicKey::from_secret_key(&secp, &spend_secret);

    let stealth_code_hash = env.stealth_lock_code_hash();

    // Create 3 stealth cells with different amounts (each with unique ephemeral key)
    let amounts = [100_00000000u64, 150_00000000u64, 250_00000000u64];

    for amount in &amounts {
        let (stealth_args, _) =
            generate_stealth_args(&view_pub, &spend_pub, &spend_secret, &view_secret);

        env.faucet
            .transfer_to_stealth(&stealth_args, &stealth_code_hash, *amount)
            .expect("Transfer should succeed");

        // Generate block after each transfer to prevent RBF conflicts
        env.generate_blocks(5).expect("Should generate blocks");
    }

    // Generate blocks to confirm - need multiple for proposal window
    env.generate_blocks(10).expect("Should generate blocks");

    // Wait for indexer to sync
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Scan and verify total
    let client = CkbRpcClient::new(DevNet::RPC_URL);
    let prefix_lock = ckb_jsonrpc_types::Script {
        code_hash: stealth_code_hash,
        hash_type: ckb_jsonrpc_types::ScriptHashType::Type,
        args: ckb_jsonrpc_types::JsonBytes::default(),
    };

    let search_key = SearchKey {
        script: prefix_lock,
        script_type: ScriptType::Lock,
        script_search_mode: Some(SearchMode::Prefix),
        filter: None,
        with_data: Some(false),
        group_by_transaction: None,
    };

    let result = client
        .get_cells(search_key, Order::Asc, 100.into(), None)
        .expect("Should get cells");

    let mut total_found = 0u64;
    let mut cell_count = 0;

    for cell in &result.objects {
        let lock_args = cell.output.lock.args.as_bytes();
        let capacity: u64 = cell.output.capacity.into();

        if verify_stealth_ownership(lock_args, &view_secret, &spend_pub) {
            total_found += capacity;
            cell_count += 1;
            println!("Found cell: {} CKB", capacity / 100_000_000);
        }
    }

    let expected_total: u64 = amounts.iter().sum();
    assert_eq!(cell_count, 3, "Should find 3 cells");
    assert_eq!(total_found, expected_total, "Total should match");

    println!(
        "Multiple cells verified: {} cells, {} CKB total",
        cell_count,
        total_found / 100_000_000
    );

    // Note: Not resetting - tests should be independent of chain state
}
