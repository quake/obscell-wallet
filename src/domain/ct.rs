//! Confidential token primitives.
//!
//! This module provides functionality for:
//! - Pedersen commitments
//! - Bulletproofs range proofs
//! - Amount encryption/decryption

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{
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
    commit(amount, &Scalar::ZERO)
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
        let input_blinding = Scalar::ZERO; // Minted cells have zero blinding

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

    #[test]
    fn test_mint_range_proof_simulation() {
        // Simulate a mint transaction as done in ct_mint.rs
        use bulletproofs::{BulletproofGens, PedersenGens};
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

        let mint_amount = 1000u64;

        // This is how ct_mint.rs creates the mint commitment (for ct-info-type verification)
        let pc_gens = PedersenGens::default();
        let mint_scalar = Scalar::from(mint_amount);
        let mint_commitment = pc_gens.commit(mint_scalar, Scalar::ZERO);
        let mint_commitment_compressed = mint_commitment.compress();

        // This is how ct-info-type contract creates the expected commitment
        // let expected_commitment = RISTRETTO_BASEPOINT_POINT * amount_scalar;
        let contract_commitment = RISTRETTO_BASEPOINT_POINT * mint_scalar;
        let contract_commitment_compressed = contract_commitment.compress();

        // Verify wallet and contract compute the same commitment
        assert_eq!(
            mint_commitment_compressed, contract_commitment_compressed,
            "Wallet mint commitment != Contract mint commitment"
        );

        // This is how ct_mint.rs generates the range proof for the minted output
        let output_blinding = Scalar::ZERO; // Mint uses zero blinding
        let (range_proof, commitments) = prove_range(&[mint_amount], &[output_blinding]).unwrap();

        // The commitment from range proof should match the mint commitment
        assert_eq!(
            mint_commitment_compressed, commitments[0],
            "Mint commitment {:?} != Range proof commitment {:?}",
            mint_commitment_compressed, commitments[0]
        );

        // Verify range proof with the commitment
        verify_range(&range_proof, &commitments).unwrap();

        // Simulate what ct-token-type does with a deterministic RNG (like TxHashRng)
        // The contract uses: rp.verify_multiple_with_rng(&bp_gens, &pc_gens, &mut transcript, &commitments, 32, &mut rng)
        let bp_gens = BulletproofGens::new(64, 1);
        let mut transcript = merlin::Transcript::new(b"ct-token-type");

        // Use a simple deterministic RNG to simulate contract behavior
        struct DeterministicRng(u64);
        impl rand_core::RngCore for DeterministicRng {
            fn next_u32(&mut self) -> u32 {
                self.next_u64() as u32
            }
            fn next_u64(&mut self) -> u64 {
                let s0 = self.0;
                let mut s1 = self.0.wrapping_add(1);
                let result = s0.wrapping_add(s1);
                s1 ^= s0;
                self.0 = s0.rotate_left(55) ^ s1 ^ (s1 << 14);
                result
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                let mut i = 0;
                while i < dest.len() {
                    let r = self.next_u64();
                    let bytes = r.to_le_bytes();
                    let take = std::cmp::min(8, dest.len() - i);
                    dest[i..i + take].copy_from_slice(&bytes[..take]);
                    i += take;
                }
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        impl rand_core::CryptoRng for DeterministicRng {}

        let mut rng = DeterministicRng(12345); // Simulate tx hash seed
        let result = range_proof.verify_multiple_with_rng(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &commitments,
            32,
            &mut rng,
        );

        assert!(
            result.is_ok(),
            "Contract-style verification failed: {:?}",
            result
        );

        // CRITICAL TEST: Simulate the exact contract flow
        // 1. Deserialize range proof from bytes (as contract does)
        let range_proof_bytes = range_proof.to_bytes();
        let deserialized_proof =
            bulletproofs::RangeProof::from_bytes(&range_proof_bytes).expect("Deserialize failed");

        // 2. Parse commitment from output data (as contract does from cell data)
        let output_data_commitment =
            CompressedRistretto::from_slice(commitments[0].as_bytes()).unwrap();

        // 3. Verify with fresh transcript (as contract does)
        let bp_gens2 = BulletproofGens::new(64, 1);
        let pc_gens2 = PedersenGens::default();
        let mut transcript2 = merlin::Transcript::new(b"ct-token-type");
        let mut rng2 = DeterministicRng(67890);

        let result2 = deserialized_proof.verify_multiple_with_rng(
            &bp_gens2,
            &pc_gens2,
            &mut transcript2,
            &[output_data_commitment],
            32,
            &mut rng2,
        );

        assert!(
            result2.is_ok(),
            "Contract-style verification (with deserialized proof) failed: {:?}",
            result2
        );

        println!("Mint simulation successful!");
        println!("  Mint amount: {}", mint_amount);
        println!("  Commitment: {:?}", hex::encode(commitments[0].as_bytes()));
        println!("  Range proof size: {} bytes", range_proof_bytes.len());
        println!("  Contract-style verification: PASSED");
        println!("  Deserialized proof verification: PASSED");
    }
}
