use color_eyre::eyre::Result;
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use crate::infra::store::Store;

use super::stealth::generate_ephemeral_key;

/// An account in the wallet, containing stealth address keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: u64,
    pub name: String,
    pub view_key: [u8; 32],
    pub spend_key: [u8; 32],
    pub ckb_balance: u64,
    pub ct_tokens: Vec<CtBalance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtBalance {
    pub token_type_hash: [u8; 32],
    pub amount: u64,
}

impl Account {
    /// Create a new account with random keys.
    pub fn new(id: u64, name: String) -> Self {
        let _secp = Secp256k1::new();
        let mut rng = OsRng;

        let view_secret = SecretKey::new(&mut rng);
        let spend_secret = SecretKey::new(&mut rng);

        Self {
            id,
            name,
            view_key: view_secret.secret_bytes(),
            spend_key: spend_secret.secret_bytes(),
            ckb_balance: 0,
            ct_tokens: Vec::new(),
        }
    }

    /// Import an account from private keys.
    pub fn from_keys(
        id: u64,
        name: String,
        view_key: [u8; 32],
        spend_key: [u8; 32],
    ) -> Result<Self> {
        // Validate keys
        SecretKey::from_slice(&view_key)?;
        SecretKey::from_slice(&spend_key)?;

        Ok(Self {
            id,
            name,
            view_key,
            spend_key,
            ckb_balance: 0,
            ct_tokens: Vec::new(),
        })
    }

    /// Get the view secret key.
    pub fn view_secret_key(&self) -> SecretKey {
        SecretKey::from_slice(&self.view_key).expect("valid view key")
    }

    /// Get the spend secret key.
    pub fn spend_secret_key(&self) -> SecretKey {
        SecretKey::from_slice(&self.spend_key).expect("valid spend key")
    }

    /// Get the view public key.
    pub fn view_public_key(&self) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &self.view_secret_key())
    }

    /// Get the spend public key.
    pub fn spend_public_key(&self) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &self.spend_secret_key())
    }

    /// Get the stealth address (view_pub || spend_pub as hex).
    pub fn stealth_address(&self) -> String {
        let view_pub = self.view_public_key().serialize();
        let spend_pub = self.spend_public_key().serialize();
        hex::encode([view_pub.as_slice(), spend_pub.as_slice()].concat())
    }

    /// Generate a one-time CKB address for receiving.
    pub fn one_time_ckb_address(&self) -> String {
        let (eph_pub, stealth_pub) =
            generate_ephemeral_key(&self.view_public_key(), &self.spend_public_key());
        let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
        let script_args = [eph_pub.serialize().as_slice(), &pubkey_hash[0..20]].concat();

        // TODO: Build proper CKB address with stealth lock code hash
        format!("ckt1...{}", hex::encode(&script_args[..8]))
    }

    /// Export private keys as hex string (view_key || spend_key).
    pub fn export_private_keys(&self) -> String {
        hex::encode([self.view_key.as_slice(), self.spend_key.as_slice()].concat())
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

    /// Create a new account with random keys.
    pub fn create_account(&mut self, name: String) -> Result<Account> {
        let accounts = self.list_accounts()?;
        let id = accounts.len() as u64;
        let account = Account::new(id, name);
        self.store.save_account(&account)?;

        if self.active_account_index.is_none() {
            self.active_account_index = Some(0);
        }

        Ok(account)
    }

    /// Import an account from private key hex (64 bytes = view_key + spend_key).
    pub fn import_account(&mut self, name: String, private_key_hex: &str) -> Result<Account> {
        let bytes = hex::decode(private_key_hex)?;
        if bytes.len() != 64 {
            return Err(color_eyre::eyre::eyre!(
                "Invalid private key length: expected 64 bytes"
            ));
        }

        let view_key: [u8; 32] = bytes[0..32].try_into()?;
        let spend_key: [u8; 32] = bytes[32..64].try_into()?;

        let accounts = self.list_accounts()?;
        let id = accounts.len() as u64;
        let account = Account::from_keys(id, name, view_key, spend_key)?;
        self.store.save_account(&account)?;

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
