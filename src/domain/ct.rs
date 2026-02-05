//! Confidential token primitives.
//!
//! This module provides functionality for:
//! - Pedersen commitments
//! - Bulletproofs range proofs
//! - Amount encryption/decryption

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use merlin::Transcript;
use rand::rngs::OsRng;

/// Create a Pedersen commitment: C = v*G + r*H
pub fn commit(value: u64, blinding: &Scalar) -> RistrettoPoint {
    let pc_gens = PedersenGens::default();
    pc_gens.commit(Scalar::from(value), *blinding)
}

/// Create a commitment with zero blinding factor (for minting).
pub fn mint_commitment(amount: u64) -> RistrettoPoint {
    commit(amount, &Scalar::zero())
}

/// Generate a random blinding factor.
pub fn random_blinding() -> Scalar {
    Scalar::random(&mut OsRng)
}

/// Generate a Bulletproof range proof for multiple values.
pub fn prove_range(
    values: &[u64],
    blindings: &[Scalar],
) -> Result<(RangeProof, Vec<CompressedRistretto>), &'static str> {
    if values.is_empty() {
        return Err("No values to prove");
    }
    if values.len() != blindings.len() {
        return Err("Values and blindings length mismatch");
    }

    let bp_gens = BulletproofGens::new(64, values.len());
    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"ct-token-type");

    RangeProof::prove_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        values,
        blindings,
        32, // 32 bits, max value 2^32 - 1
        &mut OsRng,
    )
    .map_err(|_| "Range proof generation failed")
}

/// Verify a Bulletproof range proof.
pub fn verify_range(
    proof: &RangeProof,
    commitments: &[CompressedRistretto],
) -> Result<(), &'static str> {
    if commitments.is_empty() {
        return Err("No commitments to verify");
    }

    let bp_gens = BulletproofGens::new(64, commitments.len());
    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"ct-token-type");

    proof
        .verify_multiple_with_rng(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            commitments,
            32,
            &mut OsRng,
        )
        .map_err(|_| "Range proof verification failed")
}

/// Encrypt an amount using a shared secret.
///
/// Simple XOR encryption with SHA256 hash of shared secret.
pub fn encrypt_amount(amount: u64, shared_secret: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"ct-amount-encryption");
    hasher.update(shared_secret);
    let key: [u8; 32] = hasher.finalize().into();

    let amount_bytes = amount.to_le_bytes();
    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i] = amount_bytes[i] ^ key[i];
    }
    // Fill rest with key material (for verification)
    result[8..].copy_from_slice(&key[8..]);

    result
}

/// Decrypt an amount using a shared secret.
pub fn decrypt_amount(encrypted: &[u8; 32], shared_secret: &[u8]) -> Option<u64> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"ct-amount-encryption");
    hasher.update(shared_secret);
    let key: [u8; 32] = hasher.finalize().into();

    // Verify key material matches
    if encrypted[8..] != key[8..] {
        return None;
    }

    let mut amount_bytes = [0u8; 8];
    for i in 0..8 {
        amount_bytes[i] = encrypted[i] ^ key[i];
    }

    Some(u64::from_le_bytes(amount_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment() {
        let value = 100u64;
        let blinding = random_blinding();
        let c1 = commit(value, &blinding);
        let c2 = commit(value, &blinding);
        assert_eq!(c1, c2);

        let c3 = commit(value + 1, &blinding);
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_range_proof() {
        let values = [100u64, 200u64];
        let blindings = [random_blinding(), random_blinding()];

        let (proof, commitments) = prove_range(&values, &blindings).unwrap();
        verify_range(&proof, &commitments).unwrap();
    }

    #[test]
    fn test_amount_encryption() {
        let amount = 12345678u64;
        let shared_secret = b"test shared secret";

        let encrypted = encrypt_amount(amount, shared_secret);
        let decrypted = decrypt_amount(&encrypted, shared_secret);

        assert_eq!(decrypted, Some(amount));

        // Wrong secret should fail
        let wrong = decrypt_amount(&encrypted, b"wrong secret");
        assert!(wrong.is_none());
    }

    #[test]
    fn test_transfer_commitment_balance() {
        // Simulate a transfer: 1 input (1000 tokens, zero blinding) -> 2 outputs (300 to bob, 700 change)
        let input_amount = 1000u64;
        let input_blinding = Scalar::zero(); // Minted cells have zero blinding

        // Input commitment (as stored in minted cell)
        let (_, input_commitments) = prove_range(&[input_amount], &[input_blinding]).unwrap();
        let input_commitment = input_commitments[0].decompress().unwrap();

        // Output amounts
        let bob_amount = 300u64;
        let change_amount = input_amount - bob_amount;
        assert_eq!(change_amount, 700);

        // Output blindings: random for bob, balance for change
        let bob_blinding = random_blinding();
        let change_blinding = input_blinding - bob_blinding;

        // Output commitments
        let (_, output_commitments) = prove_range(
            &[bob_amount, change_amount],
            &[bob_blinding, change_blinding],
        )
        .unwrap();

        let output_sum = output_commitments[0].decompress().unwrap()
            + output_commitments[1].decompress().unwrap();

        // Verify balance: input_sum == output_sum
        assert_eq!(
            input_commitment,
            output_sum,
            "Commitment balance failed: input {:?} != output {:?}",
            input_commitment.compress(),
            output_sum.compress()
        );
    }
}
