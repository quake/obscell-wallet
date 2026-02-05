//! End-to-end CT (confidential token) flow integration tests.
//!
//! Tests the CT token functionality:
//! 1. CT contract deployment verification
//! 2. Pedersen commitments and range proofs
//! 3. Amount encryption/decryption
//! 4. Commitment balance verification

use curve25519_dalek_ng::scalar::Scalar;

use obscell_wallet::domain::ct::{
    commit, decrypt_amount, encrypt_amount, mint_commitment, prove_range, random_blinding,
    verify_range,
};
use obscell_wallet::domain::ct_info::{CT_INFO_DATA_SIZE, CtInfoArgs, CtInfoData, MINTABLE};

use super::TestEnv;

/// Test that CT contracts are deployed and accessible.
#[test]
fn test_ct_contracts_deployed() {
    let env = TestEnv::get();

    // Verify ct-info-type is deployed
    let ct_info_type = &env.contracts.ct_info_type;
    assert!(
        ct_info_type.type_id_hash.is_some(),
        "CT-info-type contract should have type_id_hash"
    );
    assert!(
        ct_info_type.data_hash.as_bytes().iter().any(|&b| b != 0),
        "CT-info-type contract should have data_hash"
    );

    // Verify ct-token-type is deployed
    let ct_token_type = &env.contracts.ct_token_type;
    assert!(
        ct_token_type.type_id_hash.is_some(),
        "CT-token-type contract should have type_id_hash"
    );
    assert!(
        ct_token_type.data_hash.as_bytes().iter().any(|&b| b != 0),
        "CT-token-type contract should have data_hash"
    );

    println!("CT contracts verified:");
    println!(
        "  - CT-info-type tx_hash: 0x{}",
        hex::encode(ct_info_type.tx_hash.as_bytes())
    );
    println!(
        "  - CT-info-type type_id_hash: 0x{}",
        hex::encode(ct_info_type.type_id_hash.as_ref().unwrap().as_bytes())
    );
    println!(
        "  - CT-token-type tx_hash: 0x{}",
        hex::encode(ct_token_type.tx_hash.as_bytes())
    );
    println!(
        "  - CT-token-type type_id_hash: 0x{}",
        hex::encode(ct_token_type.type_id_hash.as_ref().unwrap().as_bytes())
    );
}

/// Test CT helper methods on TestEnv.
#[test]
fn test_ct_env_helpers() {
    let env = TestEnv::get();

    // Test code hash getters
    let ct_info_code_hash = env.ct_info_type_code_hash();
    assert!(
        ct_info_code_hash.as_bytes().iter().any(|&b| b != 0),
        "ct_info_type_code_hash should not be all zeros"
    );

    let ct_token_code_hash = env.ct_token_type_code_hash();
    assert!(
        ct_token_code_hash.as_bytes().iter().any(|&b| b != 0),
        "ct_token_type_code_hash should not be all zeros"
    );

    // Test data hash getters
    let ct_info_data_hash = env.ct_info_type_data_hash();
    assert!(
        ct_info_data_hash.as_bytes().iter().any(|&b| b != 0),
        "ct_info_type_data_hash should not be all zeros"
    );

    let ct_token_data_hash = env.ct_token_type_data_hash();
    assert!(
        ct_token_data_hash.as_bytes().iter().any(|&b| b != 0),
        "ct_token_type_data_hash should not be all zeros"
    );

    // Test cell dep getters
    let (ct_info_tx_hash, ct_info_index) = env.ct_info_type_cell_dep();
    assert!(
        ct_info_tx_hash.as_bytes().iter().any(|&b| b != 0),
        "ct_info_type cell dep tx_hash should not be all zeros"
    );
    assert_eq!(ct_info_index, 0, "ct_info_type cell dep index should be 0");

    let (ct_token_tx_hash, ct_token_index) = env.ct_token_type_cell_dep();
    assert!(
        ct_token_tx_hash.as_bytes().iter().any(|&b| b != 0),
        "ct_token_type cell dep tx_hash should not be all zeros"
    );
    assert_eq!(
        ct_token_index, 0,
        "ct_token_type cell dep index should be 0"
    );

    println!("CT env helpers verified:");
    println!(
        "  - ct_info_type_code_hash: 0x{}",
        hex::encode(ct_info_code_hash.as_bytes())
    );
    println!(
        "  - ct_token_type_code_hash: 0x{}",
        hex::encode(ct_token_code_hash.as_bytes())
    );
}

/// Test Pedersen commitment properties.
#[test]
fn test_pedersen_commitment_properties() {
    // Test determinism: same value and blinding = same commitment
    let value = 100u64;
    let blinding = random_blinding();
    let c1 = commit(value, &blinding);
    let c2 = commit(value, &blinding);
    assert_eq!(c1, c2, "Commitments with same inputs should be equal");

    // Test hiding: same value, different blinding = different commitment
    let blinding2 = random_blinding();
    let c3 = commit(value, &blinding2);
    assert_ne!(c1, c3, "Commitments with different blindings should differ");

    // Test binding: different value, same blinding = different commitment
    let c4 = commit(value + 1, &blinding);
    assert_ne!(c1, c4, "Commitments with different values should differ");

    // Test mint commitment (zero blinding)
    let mint_c = mint_commitment(value);
    let manual_mint = commit(value, &Scalar::zero());
    assert_eq!(
        mint_c, manual_mint,
        "Mint commitment should equal commit with zero blinding"
    );

    println!("Pedersen commitment properties verified");
}

/// Test commitment additive homomorphism.
#[test]
fn test_commitment_homomorphism() {
    let v1 = 100u64;
    let v2 = 200u64;
    let r1 = random_blinding();
    let r2 = random_blinding();

    let c1 = commit(v1, &r1);
    let c2 = commit(v2, &r2);

    // C1 + C2 = (v1 + v2)*G + (r1 + r2)*H
    let c_sum = c1 + c2;
    let expected = commit(v1 + v2, &(r1 + r2));

    assert_eq!(c_sum, expected, "Commitment addition should be homomorphic");

    println!(
        "Commitment homomorphism verified: {} + {} = {}",
        v1,
        v2,
        v1 + v2
    );
}

/// Test range proof generation and verification.
#[test]
fn test_range_proof_single_value() {
    let value = 1000u64;
    let blinding = random_blinding();

    let (proof, commitments) = prove_range(&[value], &[blinding]).expect("Proof should succeed");
    assert_eq!(commitments.len(), 1, "Should have one commitment");

    verify_range(&proof, &commitments).expect("Verification should succeed");

    println!("Single value range proof verified for value {}", value);
}

/// Test range proof with multiple values.
#[test]
fn test_range_proof_multiple_values() {
    // Bulletproofs requires the number of values to be a power of 2
    let values = [100u64, 200u64];
    let blindings = [random_blinding(), random_blinding()];

    let (proof, commitments) =
        prove_range(&values, &blindings).expect("Multi-value proof should succeed");
    assert_eq!(commitments.len(), 2, "Should have two commitments");

    verify_range(&proof, &commitments).expect("Multi-value verification should succeed");

    println!("Multi-value range proof verified for values {:?}", values);
}

/// Test range proof edge cases.
#[test]
fn test_range_proof_edge_cases() {
    // Test zero value
    let zero_blinding = random_blinding();
    let (zero_proof, zero_commitments) =
        prove_range(&[0u64], &[zero_blinding]).expect("Zero value proof should succeed");
    verify_range(&zero_proof, &zero_commitments).expect("Zero value verification should succeed");

    // Test maximum 32-bit value (2^32 - 1)
    let max_value = (1u64 << 32) - 1;
    let max_blinding = random_blinding();
    let (max_proof, max_commitments) =
        prove_range(&[max_value], &[max_blinding]).expect("Max value proof should succeed");
    verify_range(&max_proof, &max_commitments).expect("Max value verification should succeed");

    println!(
        "Range proof edge cases verified: zero and max ({})",
        max_value
    );
}

/// Test that invalid range proof fails verification.
#[test]
fn test_range_proof_invalid_verification() {
    let values = [100u64, 200u64];
    let blindings = [random_blinding(), random_blinding()];

    let (proof, _commitments) = prove_range(&values, &blindings).expect("Proof should succeed");

    // Try to verify with wrong commitments
    let wrong_blindings = [random_blinding(), random_blinding()];
    let (_, wrong_commitments) =
        prove_range(&values, &wrong_blindings).expect("Wrong proof should succeed");

    let result = verify_range(&proof, &wrong_commitments);
    assert!(
        result.is_err(),
        "Verification with wrong commitments should fail"
    );

    println!("Invalid range proof verification correctly rejected");
}

/// Test amount encryption and decryption.
#[test]
fn test_amount_encryption_roundtrip() {
    let amount = 12345678u64;
    let shared_secret = b"test shared secret for CT tokens";

    let encrypted = encrypt_amount(amount, shared_secret);
    assert_eq!(encrypted.len(), 32, "Encrypted amount should be 32 bytes");

    let decrypted = decrypt_amount(&encrypted, shared_secret);
    assert_eq!(
        decrypted,
        Some(amount),
        "Decrypted amount should match original"
    );

    println!("Amount encryption roundtrip verified for {}", amount);
}

/// Test amount decryption with wrong secret fails.
#[test]
fn test_amount_decryption_wrong_secret() {
    let amount = 999999u64;
    let correct_secret = b"correct shared secret";
    let wrong_secret = b"wrong shared secret!!!";

    let encrypted = encrypt_amount(amount, correct_secret);
    let decrypted = decrypt_amount(&encrypted, wrong_secret);

    assert!(
        decrypted.is_none(),
        "Decryption with wrong secret should fail"
    );

    println!("Wrong secret decryption correctly rejected");
}

/// Test amount encryption with various values.
#[test]
fn test_amount_encryption_various_values() {
    let test_cases = [
        0u64,             // Zero
        1u64,             // Minimum positive
        1000_00000000u64, // 1000 CKB equivalent
        u64::MAX,         // Maximum
        (1u64 << 32) - 1, // Maximum 32-bit
    ];

    for &amount in &test_cases {
        let secret = format!("secret for {}", amount);
        let encrypted = encrypt_amount(amount, secret.as_bytes());
        let decrypted = decrypt_amount(&encrypted, secret.as_bytes());

        assert_eq!(
            decrypted,
            Some(amount),
            "Roundtrip should work for amount {}",
            amount
        );
    }

    println!(
        "Amount encryption verified for {} test cases",
        test_cases.len()
    );
}

/// Test CT-Info data structure serialization.
#[test]
fn test_ct_info_data_serialization() {
    let data = CtInfoData::new(1000, 1_000_000, MINTABLE);

    let bytes = data.to_bytes();
    assert_eq!(
        bytes.len(),
        CT_INFO_DATA_SIZE,
        "Serialized size should match"
    );

    let parsed = CtInfoData::from_bytes(&bytes).expect("Parsing should succeed");
    assert_eq!(parsed.total_supply, 1000);
    assert_eq!(parsed.supply_cap, 1_000_000);
    assert_eq!(parsed.flags, MINTABLE);
    assert!(parsed.is_mintable());

    println!("CT-Info data serialization verified");
}

/// Test CT-Info minting logic.
#[test]
fn test_ct_info_minting_logic() {
    let data = CtInfoData::new(0, 1000, MINTABLE);

    // Mint 100 tokens
    let minted = data.with_minted(100).expect("First mint should succeed");
    assert_eq!(minted.total_supply, 100);

    // Mint 900 more (reach cap)
    let minted2 = minted.with_minted(900).expect("Second mint should succeed");
    assert_eq!(minted2.total_supply, 1000);

    // Try to mint more (should fail - exceeds cap)
    let result = minted2.with_minted(1);
    assert!(result.is_err(), "Minting beyond cap should fail");

    // Test unlimited supply (cap = 0)
    let unlimited = CtInfoData::new(0, 0, MINTABLE);
    assert!(
        !unlimited.would_exceed_cap(u128::MAX),
        "Unlimited supply should never exceed cap"
    );

    println!("CT-Info minting logic verified");
}

/// Test CT-Info args serialization.
#[test]
fn test_ct_info_args_serialization() {
    let token_id = [42u8; 32];
    let args = CtInfoArgs::new(token_id, 0);

    let bytes = args.to_bytes();
    assert_eq!(bytes.len(), 33, "Args should be 33 bytes");

    let parsed = CtInfoArgs::from_bytes(&bytes).expect("Parsing should succeed");
    assert_eq!(parsed.token_id, token_id);
    assert_eq!(parsed.version, 0);

    println!("CT-Info args serialization verified");
}

/// Test commitment balance for transfer scenario.
#[test]
fn test_commitment_balance_for_transfer() {
    // Simulate a transfer: input 1000, output 700 to recipient, 300 change

    let input_value = 1000u64;
    let output1_value = 700u64;
    let output2_value = 300u64;

    // Input blinding factor
    let r_in = random_blinding();

    // For balance: r_in = r_out1 + r_out2
    // We choose r_out1 randomly, then r_out2 = r_in - r_out1
    let r_out1 = random_blinding();
    let r_out2 = r_in - r_out1;

    // Create commitments
    let c_in = commit(input_value, &r_in);
    let c_out1 = commit(output1_value, &r_out1);
    let c_out2 = commit(output2_value, &r_out2);

    // Verify balance: C_in = C_out1 + C_out2
    // This works because:
    // C_in = v_in*G + r_in*H
    // C_out1 + C_out2 = (v_out1 + v_out2)*G + (r_out1 + r_out2)*H
    //                 = v_in*G + r_in*H (since v_in = v_out1 + v_out2 and r_in = r_out1 + r_out2)
    assert_eq!(
        c_in,
        c_out1 + c_out2,
        "Commitment balance should hold for transfer"
    );

    // Generate and verify range proofs for outputs
    let (proof, commitments) = prove_range(&[output1_value, output2_value], &[r_out1, r_out2])
        .expect("Range proof should succeed");
    verify_range(&proof, &commitments).expect("Range proof verification should succeed");

    println!(
        "Transfer commitment balance verified: {} -> {} + {}",
        input_value, output1_value, output2_value
    );
}

/// Test mint commitment with zero blinding.
#[test]
fn test_mint_commitment_zero_blinding() {
    let amount = 10000u64;

    // Mint commitment uses zero blinding: C = amount * G
    let c_mint = mint_commitment(amount);
    let c_manual = commit(amount, &Scalar::zero());

    assert_eq!(c_mint, c_manual, "Mint commitment should use zero blinding");

    // Verify that mint commitment can be used with range proof
    let (proof, commitments) =
        prove_range(&[amount], &[Scalar::zero()]).expect("Range proof should succeed");
    verify_range(&proof, &commitments).expect("Verification should succeed");

    // The commitment from prove_range should match our mint commitment
    let c_from_proof = commitments[0].decompress().expect("Should decompress");
    assert_eq!(
        c_mint, c_from_proof,
        "Mint commitment should match proof commitment"
    );

    println!(
        "Mint commitment with zero blinding verified for amount {}",
        amount
    );
}
