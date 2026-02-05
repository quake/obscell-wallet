use std::path::PathBuf;

use color_eyre::eyre::Result;
use heed::{byteorder::BE, types::*, Database, Env, EnvOpenOptions};
use serde::{Deserialize, Serialize};

use crate::{config::get_data_dir, domain::account::Account};

/// Wrapper around LMDB database for persistent storage.
#[derive(Clone)]
pub struct Store {
    env: Env,
}

impl Store {
    pub fn new() -> Result<Self> {
        Self::with_path(get_data_dir().join("wallet.mdb"))
    }

    pub fn with_path(path: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&path)?;
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(100 * 1024 * 1024) // 100MB
                .max_dbs(10)
                .open(path)?
        };
        Ok(Self { env })
    }

    /// Save an account to the database.
    pub fn save_account(&self, account: &Account) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let db: Database<U64<BE>, SerdeRmp<Account>> =
            self.env.create_database(&mut wtxn, Some("accounts"))?;
        db.put(&mut wtxn, &account.id, account)?;
        wtxn.commit()?;
        Ok(())
    }

    /// List all accounts.
    pub fn list_accounts(&self) -> Result<Vec<Account>> {
        let rtxn = self.env.read_txn()?;
        let db: Option<Database<U64<BE>, SerdeRmp<Account>>> =
            self.env.open_database(&rtxn, Some("accounts"))?;

        match db {
            Some(db) => {
                let mut accounts = Vec::new();
                for result in db.iter(&rtxn)? {
                    let (_, account) = result?;
                    accounts.push(account);
                }
                Ok(accounts)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Get an account by ID.
    pub fn get_account(&self, id: u64) -> Result<Option<Account>> {
        let rtxn = self.env.read_txn()?;
        let db: Option<Database<U64<BE>, SerdeRmp<Account>>> =
            self.env.open_database(&rtxn, Some("accounts"))?;

        match db {
            Some(db) => Ok(db.get(&rtxn, &id)?),
            None => Ok(None),
        }
    }

    /// Delete an account.
    pub fn delete_account(&self, id: u64) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let db: Database<U64<BE>, SerdeRmp<Account>> =
            self.env.create_database(&mut wtxn, Some("accounts"))?;
        db.delete(&mut wtxn, &id)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Save metadata (e.g., scan cursor).
    pub fn save_metadata<T: Serialize + 'static>(&self, key: &str, value: &T) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        let db: Database<Str, SerdeRmp<T>> =
            self.env.create_database(&mut wtxn, Some("metadata"))?;
        db.put(&mut wtxn, key, value)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Load metadata.
    pub fn load_metadata<T: for<'de> Deserialize<'de> + 'static>(
        &self,
        key: &str,
    ) -> Result<Option<T>> {
        let rtxn = self.env.read_txn()?;
        let db: Option<Database<Str, SerdeRmp<T>>> =
            self.env.open_database(&rtxn, Some("metadata"))?;

        match db {
            Some(db) => Ok(db.get(&rtxn, key)?),
            None => Ok(None),
        }
    }
}
