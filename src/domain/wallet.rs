//! Wallet module for BIP39 mnemonic and BIP32 key derivation.
//!
//! Implements hierarchical deterministic wallet with stealth address support.
//! Derivation path: m/44'/309'/account_index'
//!   - 309 = CKB coin type
//!   - For each account, derive view_key and spend_key from child keys.

use bip32::{Language, Mnemonic, XPrv};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::domain::crypto::{
    decrypt, decrypt_secret_key, encrypt, encrypt_secret_key, generate_salt, SALT_SIZE,
};

/// CKB coin type for BIP44 derivation.
const CKB_COIN_TYPE: u32 = 309;

/// Export format version.
const EXPORT_VERSION: u8 = 1;

/// Export prefix.
const EXPORT_PREFIX: &str = "obscell";

/// Wallet metadata stored in database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletMeta {
    /// Encrypted 64-byte seed (using passphrase).
    pub encrypted_seed: Vec<u8>,
    /// Salt for Argon2id key derivation.
    pub seed_salt: [u8; SALT_SIZE],
    /// Number of accounts derived from this wallet.
    pub account_count: u32,
}

/// Data for export (before encryption).
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct ExportData {
    mnemonic: String,
    account_count: u32,
}

/// Encrypted export format.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedExport {
    salt: [u8; SALT_SIZE],
    data: Vec<u8>, // nonce + ciphertext + tag
}

/// Generate a new 24-word mnemonic.
pub fn generate_mnemonic() -> Mnemonic {
    let mut entropy = [0u8; 32]; // 256 bits for 24 words
    OsRng.fill_bytes(&mut entropy);
    Mnemonic::from_entropy(entropy, Language::English)
}

/// Create wallet metadata from mnemonic and passphrase.
///
/// The seed is derived from mnemonic + passphrase (BIP39), then encrypted.
pub fn create_wallet_meta(
    mnemonic: &Mnemonic,
    passphrase: &str,
) -> Result<WalletMeta, &'static str> {
    // Derive seed from mnemonic (passphrase is used as BIP39 passphrase)
    let seed = mnemonic.to_seed(passphrase);

    // Generate salt for encryption
    let seed_salt = generate_salt();

    // Derive encryption key and encrypt the seed
    let key = crate::domain::crypto::derive_key(passphrase, &seed_salt)?;
    let encrypted_seed = encrypt(&key, seed.as_bytes())?;

    Ok(WalletMeta {
        encrypted_seed,
        seed_salt,
        account_count: 0,
    })
}

/// Restore wallet metadata from mnemonic and passphrase.
///
/// Used when restoring from mnemonic (not from encrypted export).
pub fn restore_wallet_meta(
    mnemonic: &Mnemonic,
    passphrase: &str,
    account_count: u32,
) -> Result<WalletMeta, &'static str> {
    let mut meta = create_wallet_meta(mnemonic, passphrase)?;
    meta.account_count = account_count;
    Ok(meta)
}

/// Decrypt seed from wallet metadata.
fn decrypt_seed(meta: &WalletMeta, passphrase: &str) -> Result<Zeroizing<[u8; 64]>, &'static str> {
    let key = crate::domain::crypto::derive_key(passphrase, &meta.seed_salt)?;
    let plaintext = decrypt(&key, &meta.encrypted_seed)?;

    if plaintext.len() != 64 {
        return Err("Decrypted seed has wrong length");
    }

    let mut seed = Zeroizing::new([0u8; 64]);
    seed.copy_from_slice(&plaintext);
    Ok(seed)
}

/// Derive view_key and spend_key for an account index.
///
/// Derivation path: m/44'/309'/account_index'/0 for view_key
///                  m/44'/309'/account_index'/1 for spend_key
pub fn derive_account_keys(
    seed: &[u8; 64],
    account_index: u32,
) -> Result<([u8; 32], [u8; 32]), &'static str> {
    // Derive: m/44'/309'/account_index'/0
    let account_path = format!("m/44'/{}'/{}'/0", CKB_COIN_TYPE, account_index);

    // Derive view_key: .../0
    let view_key_path = format!("{}/0", account_path);
    let view_xprv = XPrv::derive_from_path(seed, &view_key_path.parse().unwrap())
        .map_err(|_| "Failed to derive view key")?;

    // Derive spend_key: .../1
    let spend_key_path = format!("{}/1", account_path);
    let spend_xprv = XPrv::derive_from_path(seed, &spend_key_path.parse().unwrap())
        .map_err(|_| "Failed to derive spend key")?;

    // Extract raw private key bytes
    let view_key: [u8; 32] = view_xprv.private_key().to_bytes().into();
    let spend_key: [u8; 32] = spend_xprv.private_key().to_bytes().into();

    Ok((view_key, spend_key))
}

/// Derive keys for a new account and encrypt spend_key.
///
/// Returns (view_key, spend_public_key, encrypted_spend_key).
pub fn derive_and_encrypt_account_keys(
    meta: &WalletMeta,
    account_index: u32,
    passphrase: &str,
) -> Result<([u8; 32], Vec<u8>, Vec<u8>), &'static str> {
    let seed = decrypt_seed(meta, passphrase)?;
    let (view_key, spend_key) = derive_account_keys(&seed, account_index)?;

    // Compute spend public key before encrypting
    let spend_secret =
        secp256k1::SecretKey::from_slice(&spend_key).map_err(|_| "Invalid spend key")?;
    let secp = secp256k1::Secp256k1::new();
    let spend_public_key = secp256k1::PublicKey::from_secret_key(&secp, &spend_secret)
        .serialize()
        .to_vec();

    // Encrypt spend_key with same passphrase and salt
    let encrypted_spend_key = encrypt_secret_key(passphrase, &meta.seed_salt, &spend_key)?;

    Ok((view_key, spend_public_key, encrypted_spend_key))
}

/// Decrypt spend_key for signing.
pub fn decrypt_spend_key(
    meta: &WalletMeta,
    encrypted_spend_key: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    decrypt_secret_key(passphrase, &meta.seed_salt, encrypted_spend_key)
}

/// Verify passphrase by attempting to decrypt the seed.
pub fn verify_passphrase(meta: &WalletMeta, passphrase: &str) -> bool {
    decrypt_seed(meta, passphrase).is_ok()
}

/// Export wallet to encrypted string.
///
/// Format: obscell:1:<base64_encrypted_data>
pub fn export_wallet(
    mnemonic: &Mnemonic,
    account_count: u32,
    passphrase: &str,
) -> Result<String, &'static str> {
    let export_data = ExportData {
        mnemonic: mnemonic.phrase().to_string(),
        account_count,
    };

    // Serialize to JSON
    let json = serde_json::to_vec(&export_data).map_err(|_| "Failed to serialize export data")?;

    // Generate new salt for export encryption
    let salt = generate_salt();

    // Encrypt
    let key = crate::domain::crypto::derive_key(passphrase, &salt)?;
    let encrypted = encrypt(&key, &json)?;

    // Create export structure
    let export = EncryptedExport {
        salt,
        data: encrypted,
    };

    // Serialize and encode
    let export_bytes = serde_json::to_vec(&export).map_err(|_| "Failed to serialize export")?;
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &export_bytes);

    Ok(format!("{}:{}:{}", EXPORT_PREFIX, EXPORT_VERSION, encoded))
}

/// Import wallet from encrypted string.
///
/// Returns (mnemonic, account_count).
pub fn import_wallet(
    export_string: &str,
    passphrase: &str,
) -> Result<(Mnemonic, u32), &'static str> {
    // Parse format: obscell:1:<base64>
    let parts: Vec<&str> = export_string.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid export format");
    }

    if parts[0] != EXPORT_PREFIX {
        return Err("Invalid export prefix");
    }

    let version: u8 = parts[1].parse().map_err(|_| "Invalid version")?;
    if version != EXPORT_VERSION {
        return Err("Unsupported export version");
    }

    // Decode base64
    let export_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, parts[2])
        .map_err(|_| "Invalid base64")?;

    // Deserialize export structure
    let export: EncryptedExport =
        serde_json::from_slice(&export_bytes).map_err(|_| "Invalid export structure")?;

    // Decrypt
    let key = crate::domain::crypto::derive_key(passphrase, &export.salt)?;
    let decrypted = decrypt(&key, &export.data)?;

    // Deserialize export data
    let export_data: ExportData =
        serde_json::from_slice(&decrypted).map_err(|_| "Invalid export data")?;

    // Parse mnemonic
    let mnemonic = Mnemonic::new(export_data.mnemonic.clone(), Language::English)
        .map_err(|_| "Invalid mnemonic in export")?;

    Ok((mnemonic, export_data.account_count))
}

/// Parse mnemonic from user input (space-separated words).
pub fn parse_mnemonic(words: &str) -> Result<Mnemonic, &'static str> {
    Mnemonic::new(words.trim(), Language::English).map_err(|_| "Invalid mnemonic")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic = generate_mnemonic();
        let words: Vec<&str> = mnemonic.phrase().split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_create_and_derive_wallet() {
        let mnemonic = generate_mnemonic();
        let passphrase = "test_passphrase";

        // Create wallet
        let meta = create_wallet_meta(&mnemonic, passphrase).unwrap();

        // Derive keys for account 0
        let (view_key, _spend_public_key, encrypted_spend_key) =
            derive_and_encrypt_account_keys(&meta, 0, passphrase).unwrap();

        // Decrypt spend_key
        let spend_key = decrypt_spend_key(&meta, &encrypted_spend_key, passphrase).unwrap();

        // Keys should be valid 32-byte arrays
        assert_eq!(view_key.len(), 32);
        assert_eq!(spend_key.len(), 32);

        // Different accounts should have different keys
        let (view_key_1, _, _) = derive_and_encrypt_account_keys(&meta, 1, passphrase).unwrap();
        assert_ne!(view_key, view_key_1);
    }

    #[test]
    fn test_deterministic_derivation() {
        let mnemonic = generate_mnemonic();
        let passphrase = "test";

        let meta1 = create_wallet_meta(&mnemonic, passphrase).unwrap();
        let meta2 = create_wallet_meta(&mnemonic, passphrase).unwrap();

        // Same mnemonic + passphrase should derive same keys
        let seed1 = decrypt_seed(&meta1, passphrase).unwrap();
        let seed2 = decrypt_seed(&meta2, passphrase).unwrap();

        let (view1, spend1) = derive_account_keys(&seed1, 0).unwrap();
        let (view2, spend2) = derive_account_keys(&seed2, 0).unwrap();

        assert_eq!(view1, view2);
        assert_eq!(spend1, spend2);
    }

    #[test]
    fn test_export_import_roundtrip() {
        let mnemonic = generate_mnemonic();
        let passphrase = "export_test";
        let account_count = 3;

        // Export
        let export_string = export_wallet(&mnemonic, account_count, passphrase).unwrap();
        assert!(export_string.starts_with("obscell:1:"));

        // Import
        let (imported_mnemonic, imported_count) =
            import_wallet(&export_string, passphrase).unwrap();

        assert_eq!(imported_mnemonic.phrase(), mnemonic.phrase());
        assert_eq!(imported_count, account_count);
    }

    #[test]
    fn test_wrong_passphrase_import_fails() {
        let mnemonic = generate_mnemonic();
        let export_string = export_wallet(&mnemonic, 1, "correct").unwrap();

        let result = import_wallet(&export_string, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_passphrase() {
        let mnemonic = generate_mnemonic();
        let meta = create_wallet_meta(&mnemonic, "correct").unwrap();

        assert!(verify_passphrase(&meta, "correct"));
        assert!(!verify_passphrase(&meta, "wrong"));
    }
}
