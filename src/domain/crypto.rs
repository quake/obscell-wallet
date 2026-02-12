//! Cryptographic utilities for wallet encryption.
//!
//! Uses Argon2id for key derivation and ChaCha20-Poly1305 for encryption.

use argon2::{Argon2, ParamsBuilder};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

/// Argon2id parameters for key derivation.
/// Tuned for ~0.5s on modern hardware.
const ARGON2_M_COST: u32 = 64 * 1024; // 64 MB
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 4; // 4 parallelism

/// Salt size for Argon2.
pub const SALT_SIZE: usize = 16;

/// Nonce size for ChaCha20-Poly1305.
pub const NONCE_SIZE: usize = 12;

/// Authentication tag size for ChaCha20-Poly1305.
pub const TAG_SIZE: usize = 16;

/// Derive a 32-byte encryption key from a passphrase using Argon2id.
pub fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_SIZE],
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let params = ParamsBuilder::new()
        .m_cost(ARGON2_M_COST)
        .t_cost(ARGON2_T_COST)
        .p_cost(ARGON2_P_COST)
        .build()
        .map_err(|_| "Failed to build Argon2 params")?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| "Failed to derive key")?;

    Ok(key)
}

/// Generate a random salt.
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a random nonce.
fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypt data using ChaCha20-Poly1305.
///
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| "Invalid key length")?;

    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "Encryption failed")?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data using ChaCha20-Poly1305.
///
/// Input format: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn decrypt(key: &[u8; 32], encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if encrypted.len() < NONCE_SIZE + TAG_SIZE {
        return Err("Encrypted data too short");
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| "Invalid key length")?;

    let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
    let ciphertext = &encrypted[NONCE_SIZE..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed (wrong passphrase?)")?;

    Ok(Zeroizing::new(plaintext))
}

/// Encrypt a 32-byte secret key.
///
/// Returns: nonce (12) + ciphertext (32) + tag (16) = 60 bytes
pub fn encrypt_secret_key(
    passphrase: &str,
    salt: &[u8; SALT_SIZE],
    secret_key: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    let key = derive_key(passphrase, salt)?;
    encrypt(&key, secret_key)
}

/// Decrypt a 32-byte secret key.
pub fn decrypt_secret_key(
    passphrase: &str,
    salt: &[u8; SALT_SIZE],
    encrypted: &[u8],
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let key = derive_key(passphrase, salt)?;
    let plaintext = decrypt(&key, encrypted)?;

    if plaintext.len() != 32 {
        return Err("Decrypted key has wrong length");
    }

    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(&plaintext);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let passphrase = "test_password_123";
        let salt = generate_salt();
        let secret = [42u8; 32];

        let encrypted = encrypt_secret_key(passphrase, &salt, &secret).unwrap();
        assert_eq!(encrypted.len(), NONCE_SIZE + 32 + TAG_SIZE); // 60 bytes

        let decrypted = decrypt_secret_key(passphrase, &salt, &encrypted).unwrap();
        assert_eq!(*decrypted, secret);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let salt = generate_salt();
        let secret = [42u8; 32];

        let encrypted = encrypt_secret_key("correct", &salt, &secret).unwrap();
        let result = decrypt_secret_key("wrong", &salt, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_different_salt_fails() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let secret = [42u8; 32];

        let encrypted = encrypt_secret_key("password", &salt1, &secret).unwrap();
        let result = decrypt_secret_key("password", &salt2, &encrypted);

        assert!(result.is_err());
    }
}
