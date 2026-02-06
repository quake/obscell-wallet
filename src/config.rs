use std::path::PathBuf;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

/// Get the data directory for the application.
pub fn get_data_dir() -> PathBuf {
    if let Ok(s) = std::env::var("OBSCELL_WALLET_DATA") {
        PathBuf::from(s)
    } else if let Some(proj_dirs) = ProjectDirs::from("com", "obscell", "obscell-wallet") {
        proj_dirs.data_local_dir().to_path_buf()
    } else {
        PathBuf::from(".").join(".data")
    }
}

/// Get the config directory for the application.
pub fn get_config_dir() -> PathBuf {
    if let Ok(s) = std::env::var("OBSCELL_WALLET_CONFIG") {
        PathBuf::from(s)
    } else if let Some(proj_dirs) = ProjectDirs::from("com", "obscell", "obscell-wallet") {
        proj_dirs.config_local_dir().to_path_buf()
    } else {
        PathBuf::from(".").join(".config")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub name: String,
    pub rpc_url: String,
    pub indexer_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractConfig {
    pub stealth_lock_code_hash: String,
    pub ct_token_code_hash: String,
    pub ct_info_code_hash: String,
    pub ckb_auth_code_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellDepConfig {
    pub tx_hash: String,
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub network: NetworkConfig,
    pub contracts: ContractConfig,
    pub cell_deps: CellDepsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellDepsConfig {
    pub ckb_auth: CellDepConfig,
    pub stealth_lock: CellDepConfig,
    pub ct_token: CellDepConfig,
    pub ct_info: CellDepConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self::testnet()
    }
}

impl Config {
    /// Create config from CLI args.
    pub fn new(network: &str, rpc_url: Option<&str>) -> Self {
        let mut config = Self::from_network(network);
        if let Some(url) = rpc_url {
            config.network.rpc_url = url.to_string();
            // Also update indexer URL if it's the default pattern
            if config.network.indexer_url.ends_with("/indexer") {
                config.network.indexer_url = format!("{}/indexer", url);
            }
        }
        config
    }

    pub fn testnet() -> Self {
        Self {
            network: NetworkConfig {
                name: "testnet".to_string(),
                rpc_url: "https://testnet.ckb.dev".to_string(),
                indexer_url: "https://testnet.ckb.dev/indexer".to_string(),
            },
            contracts: ContractConfig {
                stealth_lock_code_hash:
                    "0x1d7f12a173ed22df9de1180a0b11e2a4368568017d9cfdfb5658b50c147549d6".to_string(),
                ct_token_code_hash:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ct_info_code_hash:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ckb_auth_code_hash:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            },
            cell_deps: CellDepsConfig {
                ckb_auth: CellDepConfig {
                    tx_hash: "0x91b7a8e6fdeef45389dee510a1f070dc764855f72b08b24165d9c92ef36ff920"
                        .to_string(),
                    index: 0,
                },
                stealth_lock: CellDepConfig {
                    tx_hash: "0x91b7a8e6fdeef45389dee510a1f070dc764855f72b08b24165d9c92ef36ff920"
                        .to_string(),
                    index: 1,
                },
                ct_token: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 0,
                },
                ct_info: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 0,
                },
            },
        }
    }

    pub fn mainnet() -> Self {
        Self {
            network: NetworkConfig {
                name: "mainnet".to_string(),
                rpc_url: "https://mainnet.ckb.dev".to_string(),
                indexer_url: "https://mainnet.ckb.dev/indexer".to_string(),
            },
            contracts: ContractConfig {
                stealth_lock_code_hash:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ct_token_code_hash:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ct_info_code_hash:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ckb_auth_code_hash:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            },
            cell_deps: CellDepsConfig {
                ckb_auth: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 0,
                },
                stealth_lock: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 1,
                },
                ct_token: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 0,
                },
                ct_info: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 0,
                },
            },
        }
    }

    pub fn devnet() -> Self {
        Self {
            network: NetworkConfig {
                name: "devnet".to_string(),
                rpc_url: "http://127.0.0.1:8114".to_string(),
                indexer_url: "http://127.0.0.1:8114/indexer".to_string(),
            },
            contracts: ContractConfig {
                stealth_lock_code_hash:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ct_token_code_hash:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ct_info_code_hash:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                ckb_auth_code_hash:
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            },
            cell_deps: CellDepsConfig {
                ckb_auth: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 0,
                },
                stealth_lock: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 1,
                },
                ct_token: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 0,
                },
                ct_info: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 0,
                },
            },
        }
    }

    pub fn from_network(network: &str) -> Self {
        match network {
            "mainnet" => Self::mainnet(),
            "devnet" => Self::devnet(),
            _ => Self::testnet(),
        }
    }
}
