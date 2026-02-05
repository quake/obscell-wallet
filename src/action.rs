use serde::{Deserialize, Serialize};
use strum::Display;

/// Actions that can be triggered by user input or internal events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Display)]
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
    TabAccounts,
    TabSend,
    TabReceive,
    TabTokens,
    TabHistory,

    // Account actions
    CreateAccount,
    ImportAccount,
    ExportAccount,
    SelectAccount(usize),
    DeleteAccount,

    // Transaction actions
    SendTransaction,
    Rescan,

    // Token actions
    MintToken,
    CreateToken,

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
}
