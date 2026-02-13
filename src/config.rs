use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Global data directory override (set from CLI args at startup)
static DATA_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Global config directory override (set from CLI args at startup)
static CONFIG_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Set the data directory override (call once at startup before any other access)
pub fn set_data_dir(path: PathBuf) {
    let _ = DATA_DIR_OVERRIDE.set(path);
}

/// Set the config directory override (call once at startup before any other access)
pub fn set_config_dir(path: PathBuf) {
    let _ = CONFIG_DIR_OVERRIDE.set(path);
}

/// Get the base data directory for the application.
/// Default: ./data
pub fn get_data_dir() -> PathBuf {
    if let Some(path) = DATA_DIR_OVERRIDE.get() {
        path.clone()
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
/// This is only used when --config-dir is specified.
/// Returns None if no override is set (config files are searched in current dir).
pub fn get_config_dir() -> Option<PathBuf> {
    CONFIG_DIR_OVERRIDE.get().cloned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub name: String,
    pub rpc_url: String,
    /// Block number to start scanning from (default: 0).
    /// Set this to the stealth-lock deployment height to skip scanning old blocks.
    #[serde(default)]
    pub scan_start_block: u64,
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
        }
        config
    }

    pub fn testnet() -> Self {
        Self {
            network: NetworkConfig {
                name: "testnet".to_string(),
                rpc_url: "https://testnet.ckb.dev".to_string(),
                scan_start_block: 0, // Will be updated when stealth-lock is deployed
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
                scan_start_block: 0, // Will be updated when stealth-lock is deployed
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

    /// Devnet configuration with deterministic contract addresses.
    /// These addresses are stable when using genesis message "obscell-wallet-test".
    /// Run integration tests once to deploy contracts before using the wallet.
    pub fn devnet() -> Self {
        Self {
            network: NetworkConfig {
                name: "devnet".to_string(),
                rpc_url: "http://127.0.0.1:8114".to_string(),
                scan_start_block: 0, // Devnet starts fresh
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
                },
                stealth_lock: CellDepConfig {
                    tx_hash: "0x71c34864af8700efcc7346ece7aeb83d13fea99eae7a341cab30d1672c69bd0c"
                        .to_string(),
                    index: 0,
                },
                ct_token: CellDepConfig {
                    tx_hash: "0x4e2fdebd1e5348b932e2cc3ffbdb1c89a44df9a3f5946e17a874ed0c9580fb89"
                        .to_string(),
                    index: 0,
                },
                ct_info: CellDepConfig {
                    tx_hash: "0xa44bca576ae0aae6e797da31709cb442f50cda74b8863d479563e88fefdf4fd4"
                        .to_string(),
                    index: 0,
                },
            },
        }
    }

    /// Load config from network name.
    ///
    /// Tries to load from config file first, falls back to hardcoded defaults.
    /// Config file search order:
    /// 1. `--config-dir/{network}.toml` (if specified via CLI)
    /// 2. `./{network}.toml` (current directory)
    /// 3. `./config/{network}.toml` (config subdirectory)
    /// 4. Hardcoded defaults
    pub fn from_network(network: &str) -> Self {
        // Try to load from config file
        if let Some(config) = Self::load_from_file(network) {
            info!("Loaded config from file for network: {}", network);
            debug!(
                "Using stealth_lock_code_hash: {}",
                config.contracts.stealth_lock_code_hash
            );
            return config;
        }

        // Fall back to hardcoded defaults
        warn!(
            "No config file found for network '{}', using hardcoded defaults",
            network
        );
        let config = match network {
            "mainnet" => Self::mainnet(),
            "devnet" => Self::devnet(),
            _ => Self::testnet(),
        };
        debug!(
            "Using hardcoded stealth_lock_code_hash: {}",
            config.contracts.stealth_lock_code_hash
        );
        config
    }

    /// Try to load config from file.
    fn load_from_file(network: &str) -> Option<Self> {
        let filename = format!("{}.toml", network);

        // Build search paths in order of priority
        let mut search_paths = Vec::new();

        // 1. If --config-dir is specified, search there first
        if let Some(config_dir) = get_config_dir() {
            search_paths.push(config_dir.join(&filename));
        }

        // 2. Current directory ./{network}.toml
        search_paths.push(PathBuf::from(&filename));

        // 3. Config subdirectory ./config/{network}.toml
        search_paths.push(PathBuf::from("config").join(&filename));

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_devnet_config_loads_from_file() {
        // This test verifies that devnet config is loaded from config/devnet.toml
        // and NOT using the hardcoded defaults
        let config = Config::from_network("devnet");

        // Print actual loaded value for debugging
        println!(
            "Loaded stealth_lock_code_hash: {}",
            config.contracts.stealth_lock_code_hash
        );
        println!("Loaded from network: {}", config.network.name);

        // The config/devnet.toml has this code_hash (updated by contract deployment):
        let devnet_toml_code_hash =
            "0xc6abe10f415dc7727058a7afd50fa4f3a22e316b38173a5b1b259cd766e7cb87";

        // The hardcoded Config::devnet() has:
        // 0xe5e49e1d9e89a41e74830c2286489876723b976b530214ac00318a933f7b3335
        // The testnet has:
        // 0x1d7f12a173ed22df9de1180a0b11e2a4368568017d9cfdfb5658b50c147549d6

        let testnet_code_hash =
            "0x1d7f12a173ed22df9de1180a0b11e2a4368568017d9cfdfb5658b50c147549d6";

        assert_ne!(
            config.contracts.stealth_lock_code_hash, testnet_code_hash,
            "Devnet config should NOT use testnet stealth_lock_code_hash! \
             This means config/devnet.toml is not being loaded correctly."
        );

        assert_eq!(
            config.contracts.stealth_lock_code_hash, devnet_toml_code_hash,
            "Devnet config should load stealth_lock_code_hash from config/devnet.toml"
        );

        assert_eq!(
            config.network.name, "devnet",
            "Network name should be devnet"
        );
    }
}
