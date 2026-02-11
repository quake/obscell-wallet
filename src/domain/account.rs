use color_eyre::eyre::Result;
#[cfg(any(test, feature = "test-utils"))]
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::infra::store::Store;

use super::stealth::generate_ephemeral_key;
use super::wallet::WalletMeta;

/// An account in the wallet, containing stealth address keys.
///
/// The view_key and spend_public_key are stored in plaintext for scanning without password.
/// The spend_key is encrypted and requires passphrase to decrypt for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: u64,
    pub name: String,
    /// Derivation index in HD wallet (m/44'/309'/derivation_index'/...)
    pub derivation_index: u32,
    /// View key (plaintext) - used for scanning without password
    pub view_key: [u8; 32],
    /// Spend public key (plaintext) - used for scanning without password
    /// Stored as 33-byte compressed public key
    pub spend_public_key: Vec<u8>,
    /// Encrypted spend key - requires passphrase to decrypt for signing
    pub encrypted_spend_key: Vec<u8>,
    pub ckb_balance: u64,
    pub ct_tokens: Vec<CtBalance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtBalance {
    pub token_type_hash: [u8; 32],
    pub amount: u64,
}

impl Account {
    /// Create a new account from HD wallet derivation.
    pub fn new(
        id: u64,
        name: String,
        derivation_index: u32,
        view_key: [u8; 32],
        spend_public_key: Vec<u8>,
        encrypted_spend_key: Vec<u8>,
    ) -> Self {
        Self {
            id,
            name,
            derivation_index,
            view_key,
            spend_public_key,
            encrypted_spend_key,
            ckb_balance: 0,
            ct_tokens: Vec::new(),
        }
    }

    /// Create a new account with random keys (for testing only).
    ///
    /// WARNING: This creates an account with an unencrypted spend_key stored in
    /// encrypted_spend_key field. Only use for testing purposes.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_random(id: u64, name: String) -> Self {
        let secp = Secp256k1::new();
        let mut rng = OsRng;

        let view_secret = SecretKey::new(&mut rng);
        let spend_secret = SecretKey::new(&mut rng);

        let view_key = view_secret.secret_bytes();
        let spend_public_key = PublicKey::from_secret_key(&secp, &spend_secret)
            .serialize()
            .to_vec();
        // For testing, store spend_key unencrypted (this is not secure!)
        let encrypted_spend_key = spend_secret.secret_bytes().to_vec();

        Self {
            id,
            name,
            derivation_index: id as u32,
            view_key,
            spend_public_key,
            encrypted_spend_key,
            ckb_balance: 0,
            ct_tokens: Vec::new(),
        }
    }

    /// Get the spend secret key directly (for testing only).
    ///
    /// This only works with accounts created by `new_random()`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn spend_secret_key_for_test(&self) -> SecretKey {
        SecretKey::from_slice(&self.encrypted_spend_key).expect("valid spend key (test only)")
    }

    /// Get the view secret key.
    pub fn view_secret_key(&self) -> SecretKey {
        SecretKey::from_slice(&self.view_key).expect("valid view key")
    }

    /// Decrypt and get the spend secret key.
    ///
    /// This requires the wallet metadata and passphrase.
    pub fn decrypt_spend_key(
        &self,
        wallet_meta: &WalletMeta,
        passphrase: &str,
    ) -> Result<Zeroizing<[u8; 32]>, &'static str> {
        super::wallet::decrypt_spend_key(wallet_meta, &self.encrypted_spend_key, passphrase)
    }

    /// Get the view public key.
    pub fn view_public_key(&self) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &self.view_secret_key())
    }

    /// Get the spend public key (no passphrase needed - stored in plaintext).
    pub fn spend_public_key(&self) -> PublicKey {
        PublicKey::from_slice(&self.spend_public_key).expect("valid spend public key")
    }

    /// Get the stealth address (view_pub || spend_pub as hex).
    pub fn stealth_address(&self) -> String {
        let view_pub = self.view_public_key().serialize();
        let spend_pub = &self.spend_public_key;
        hex::encode([view_pub.as_slice(), spend_pub.as_slice()].concat())
    }

    /// Generate a one-time CKB address for receiving.
    pub fn one_time_ckb_address(&self, is_mainnet: bool) -> String {
        let (eph_pub, stealth_pub) =
            generate_ephemeral_key(&self.view_public_key(), &self.spend_public_key());
        let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
        let script_args = [eph_pub.serialize().as_slice(), &pubkey_hash[0..20]].concat();

        let prefix = if is_mainnet { "ckb" } else { "ckt" };
        format!("{}...{}", prefix, hex::encode(&script_args[..8]))
    }
}

/// Manages accounts in the wallet.
pub struct AccountManager {
    store: Store,
    active_account_index: Option<usize>,
}

impl AccountManager {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            active_account_index: None,
        }
    }

    /// Create a new account from HD wallet.
    ///
    /// Derives keys from wallet metadata using the next derivation index.
    pub fn create_account(
        &mut self,
        name: String,
        wallet_meta: &mut WalletMeta,
        passphrase: &str,
    ) -> Result<Account> {
        let accounts = self.list_accounts()?;
        let id = accounts.len() as u64;
        let derivation_index = wallet_meta.account_count;

        // Derive keys for this account
        let (view_key, spend_public_key, encrypted_spend_key) =
            super::wallet::derive_and_encrypt_account_keys(
                wallet_meta,
                derivation_index,
                passphrase,
            )
            .map_err(|e| color_eyre::eyre::eyre!("{}", e))?;

        let account = Account::new(
            id,
            name,
            derivation_index,
            view_key,
            spend_public_key,
            encrypted_spend_key,
        );
        self.store.save_account(&account)?;

        // Increment account count
        wallet_meta.account_count += 1;
        self.store.save_wallet_meta(wallet_meta)?;

        if self.active_account_index.is_none() {
            self.active_account_index = Some(0);
        }

        Ok(account)
    }

    /// List all accounts.
    pub fn list_accounts(&self) -> Result<Vec<Account>> {
        self.store.list_accounts()
    }

    /// Get the active account.
    pub fn active_account(&self) -> Result<Option<Account>> {
        match self.active_account_index {
            Some(index) => {
                let accounts = self.list_accounts()?;
                Ok(accounts.into_iter().nth(index))
            }
            None => Ok(None),
        }
    }

    /// Set the active account by index.
    pub fn set_active_account(&mut self, index: usize) -> Result<()> {
        let accounts = self.list_accounts()?;
        if index >= accounts.len() {
            return Err(color_eyre::eyre::eyre!("Account index out of bounds"));
        }
        self.active_account_index = Some(index);
        Ok(())
    }

    /// Update an account's balance.
    pub fn update_balance(&mut self, account_id: u64, balance: u64) -> Result<()> {
        let mut accounts = self.list_accounts()?;
        if let Some(acc) = accounts.iter_mut().find(|a| a.id == account_id) {
            acc.ckb_balance = balance;
            self.store.save_account(acc)?;
        }
        Ok(())
    }
}
