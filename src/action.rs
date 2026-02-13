use serde::{Deserialize, Serialize};
use strum::Display;

use crate::infra::block_scanner::BlockScanUpdate;

/// Purpose of the passphrase popup - determines what action to take after passphrase is entered
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PassphrasePurpose {
    /// Sign and send a CKB transaction
    SendTransaction,
    /// Create a new account
    CreateAccount,
    /// Export wallet backup
    ExportBackup,
    /// Transfer token
    TransferToken,
    /// Mint token
    MintToken,
    /// Create (genesis) token
    CreateToken,
}

/// Actions that can be triggered by user input or internal events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Action {
    Tick,
    Render,
    Resize(u16, u16),
    Suspend,
    Resume,
    Quit,
    ClearScreen,
    Error(String),
    Help,

    // Navigation
    FocusNext,
    FocusPrev,
    Submit,
    Cancel,

    // Tab switching
    TabSettings,
    TabAccounts,
    TabSend,
    TabTokens,
    TabHistory,

    // Settings actions
    SwitchNetwork(String),
    ExportWalletBackup,
    ExportWalletBackupWithPassphrase(String),
    SaveBackupToFile(String),

    // Account actions
    CreateAccount,
    CreateAccountWithPassphrase(String),
    ImportAccount,
    ExportAccount,
    SelectAccount(usize),
    DeleteAccount,
    /// Toggle one-time address spinning (stop/start rotation)
    ToggleAddressSpinning,

    // Transaction actions
    SendTransaction,
    SendTransactionWithPassphrase(String),
    Rescan,
    FullRescan,
    /// Full rescan starting from a specific block height
    FullRescanFromHeight(u64),

    // Background scan updates
    ScanProgress(BlockScanUpdate),

    // Token actions
    SelectToken(usize),
    TransferToken,
    TransferTokenWithPassphrase(String),
    MintToken,
    MintTokenWithPassphrase(String),
    CreateToken,
    CreateTokenWithPassphrase(String),

    // Input handling
    EnterInput,
    ExitInput,
    InputChar(char),
    InputBackspace,
    InputDelete,

    // Passphrase popup actions
    /// Show the passphrase popup for a specific purpose
    ShowPassphrasePopup(PassphrasePurpose),
    /// Cancel and close the passphrase popup
    CancelPassphrasePopup,
    /// Confirm the passphrase (triggered by Enter in popup)
    ConfirmPassphrase(String),

    // Transaction progress popup actions
    /// Show the transaction progress spinner
    ShowTxProgress,
    /// Hide the transaction progress spinner
    HideTxProgress,
    /// Transaction completed successfully (with purpose to clear the right form)
    TxSuccess(PassphrasePurpose, String),
    /// Transaction failed with error message
    TxError(String),
    /// Passphrase verification failed (re-show popup with error)
    PassphraseError(PassphrasePurpose, String),

    // Account creation (background thread results)
    /// Account keys derived successfully: (view_key, spend_public_key, encrypted_spend_key, derivation_index)
    AccountKeysReady {
        view_key: [u8; 32],
        spend_public_key: Vec<u8>,
        encrypted_spend_key: Vec<u8>,
        derivation_index: u32,
    },

    // Wallet creation (background thread results)
    /// Wallet and first account created successfully
    WalletReady {
        wallet_meta: crate::domain::wallet::WalletMeta,
        account: crate::domain::account::Account,
        status_message: String,
    },
    /// Wallet creation failed with error message
    WalletError(String),

    // Scrolling
    ScrollUp,
    ScrollDown,
    PageUp,
    PageDown,
    Home,
    End,

    // Dev mode actions
    TabDev,
    GenerateBlock,
    GenerateBlocks(u64),
    SaveCheckpoint,
    ResetToCheckpoint,
    ToggleAutoMining,
    SetMiningInterval(u64),
    SendFaucet,
    RefreshDevStatus,

    // Wallet setup actions
    GenerateMnemonic,
    CreateWallet,
    RestoreFromMnemonic,
    RestoreFromBackup,
    WalletSetupComplete,
}
