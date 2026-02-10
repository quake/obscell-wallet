use std::path::PathBuf;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Get the base data directory for the application.
pub fn get_data_dir() -> PathBuf {
    if let Ok(s) = std::env::var("OBSCELL_WALLET_DATA") {
        PathBuf::from(s)
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("data")
    }
}

/// Get the network-specific data directory (e.g. `data/testnet/`).
pub fn get_network_data_dir(network: &str) -> PathBuf {
    get_data_dir().join(network)
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CellDepConfig {
    #[serde(default)]
    pub tx_hash: String,
    #[serde(default)]
    pub index: u32,
    #[serde(default)]
    pub data_hash: Option<String>,
    #[serde(default)]
    pub type_id_hash: Option<String>,
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
                    ..Default::default()
                },
                stealth_lock: CellDepConfig {
                    tx_hash: "0x91b7a8e6fdeef45389dee510a1f070dc764855f72b08b24165d9c92ef36ff920"
                        .to_string(),
                    index: 1,
                    ..Default::default()
                },
                ct_token: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 0,
                    ..Default::default()
                },
                ct_info: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 0,
                    ..Default::default()
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
                    ..Default::default()
                },
                stealth_lock: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 1,
                    ..Default::default()
                },
                ct_token: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 0,
                    ..Default::default()
                },
                ct_info: CellDepConfig {
                    tx_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                    index: 0,
                    ..Default::default()
                },
            },
        }
    }

    /// Devnet configuration with deterministic contract addresses.
    /// These addresses are stable when using genesis message "obscell-wallet-test".
    /// Run integration tests once to deploy contracts before using the wallet.
    pub fn devnet() -> Self {
        Self {
            network: NetworkConfig {
                name: "devnet".to_string(),
                rpc_url: "http://127.0.0.1:8114".to_string(),
                indexer_url: "http://127.0.0.1:8114/indexer".to_string(),
            },
            contracts: ContractConfig {
                stealth_lock_code_hash:
                    "0xe5e49e1d9e89a41e74830c2286489876723b976b530214ac00318a933f7b3335".to_string(),
                ct_token_code_hash:
                    "0x328278274e32b6fd33deedabfb1dfbd6c8dde7d2b6c5fb5fb3a864fc43bb9fea".to_string(),
                ct_info_code_hash:
                    "0xadb7badbb57e9712ed1d95bec81287a2329afb7c3ff1d55ac75cbac178da06b7".to_string(),
                ckb_auth_code_hash:
                    "0x24cbc0576afd0bb1e73871363d4724d5a09f428c16090a0f2cb71de6a4221372".to_string(),
            },
            cell_deps: CellDepsConfig {
                ckb_auth: CellDepConfig {
                    tx_hash: "0x87c82ca69e0e8273320120e17667b6264818cc7cc6e9cad58eb08452d933efef"
                        .to_string(),
                    index: 0,
                    ..Default::default()
                },
                stealth_lock: CellDepConfig {
                    tx_hash: "0x71c34864af8700efcc7346ece7aeb83d13fea99eae7a341cab30d1672c69bd0c"
                        .to_string(),
                    index: 0,
                    ..Default::default()
                },
                ct_token: CellDepConfig {
                    tx_hash: "0x4e2fdebd1e5348b932e2cc3ffbdb1c89a44df9a3f5946e17a874ed0c9580fb89"
                        .to_string(),
                    index: 0,
                    ..Default::default()
                },
                ct_info: CellDepConfig {
                    tx_hash: "0xa44bca576ae0aae6e797da31709cb442f50cda74b8863d479563e88fefdf4fd4"
                        .to_string(),
                    index: 0,
                    ..Default::default()
                },
            },
        }
    }

    /// Load config from network name.
    ///
    /// Tries to load from config file first, falls back to hardcoded defaults.
    /// Config file search order:
    /// 1. `./config/{network}.toml` (project directory)
    /// 2. `$OBSCELL_WALLET_CONFIG/{network}.toml` (env var)
    /// 3. System config directory `/{network}.toml`
    /// 4. Hardcoded defaults
    pub fn from_network(network: &str) -> Self {
        // Try to load from config file
        if let Some(config) = Self::load_from_file(network) {
            info!("Loaded config from file for network: {}", network);
            return config;
        }

        // Fall back to hardcoded defaults
        debug!(
            "No config file found for network '{}', using hardcoded defaults",
            network
        );
        match network {
            "mainnet" => Self::mainnet(),
            "devnet" => Self::devnet(),
            _ => Self::testnet(),
        }
    }

    /// Try to load config from file.
    fn load_from_file(network: &str) -> Option<Self> {
        let filename = format!("{}.toml", network);

        // Search paths in order of priority
        let search_paths = vec![
            // 1. Project directory ./config/
            PathBuf::from("config").join(&filename),
            // 2. System config directory
            get_config_dir().join(&filename),
        ];

        for path in search_paths {
            if path.exists() {
                match std::fs::read_to_string(&path) {
                    Ok(content) => match toml::from_str::<Config>(&content) {
                        Ok(mut config) => {
                            // Ensure network name matches
                            config.network.name = network.to_string();
                            info!("Loaded config from: {}", path.display());
                            return Some(config);
                        }
                        Err(e) => {
                            warn!("Failed to parse config file {}: {}", path.display(), e);
                        }
                    },
                    Err(e) => {
                        warn!("Failed to read config file {}: {}", path.display(), e);
                    }
                }
            }
        }

        None
    }

    /// Save config to file.
    pub fn save_to_file(&self, path: &PathBuf) -> Result<(), String> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }

        std::fs::write(path, content).map_err(|e| format!("Failed to write config file: {}", e))?;

        Ok(())
    }
}
