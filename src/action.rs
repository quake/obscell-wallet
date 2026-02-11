use serde::{Deserialize, Serialize};
use strum::Display;

use crate::infra::scanner::ScanUpdate;

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
    TabReceive,
    TabTokens,
    TabHistory,

    // Settings actions
    SwitchNetwork(String),
    ExportWalletBackup,
    ExportWalletBackupWithPassphrase(String),

    // Account actions
    CreateAccount,
    ImportAccount,
    ExportAccount,
    SelectAccount(usize),
    DeleteAccount,

    // Transaction actions
    SendTransaction,
    SendTransactionWithPassphrase(String),
    Rescan,
    FullRescan,

    // Background scan updates
    ScanProgress(ScanUpdate),

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
