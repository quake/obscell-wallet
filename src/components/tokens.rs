//! Tokens component for displaying and managing CT token balances.

use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    action::{Action, PassphrasePurpose},
    domain::{
        account::Account,
        cell::{CtBalance, CtCell},
    },
    tui::Frame,
};

use super::Component;

/// Token view mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokensMode {
    /// List token balances.
    List,
    /// Context menu for token operations (Transfer/Mint).
    ContextMenu,
    /// Transfer tokens.
    Transfer,
    /// Mint tokens (issuer only).
    Mint,
    /// Create new token (genesis).
    Genesis,
}

/// Context menu operations (shown when pressing Enter on a token).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextMenuOperation {
    Transfer,
    Mint,
}

impl ContextMenuOperation {
    fn all() -> &'static [ContextMenuOperation] {
        &[ContextMenuOperation::Transfer, ContextMenuOperation::Mint]
    }

    fn label(&self) -> &'static str {
        match self {
            ContextMenuOperation::Transfer => "Transfer",
            ContextMenuOperation::Mint => "Mint",
        }
    }
}

/// Input field focus state for transfer mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferField {
    Recipient,
    Amount,
    Confirm,
}

/// Input field focus state for genesis mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisField {
    SupplyCap,
    Unlimited,
    Confirm,
}

/// Component for displaying and managing CT token balances.
pub struct TokensComponent {
    action_tx: UnboundedSender<Action>,
    pub account: Option<Account>,
    pub balances: Vec<CtBalance>,
    pub ct_cells: Vec<CtCell>,
    /// Selected index in the list. Index == balances.len() means "Create New Token" is selected.
    pub selected_index: usize,
    list_state: ListState,
    pub mode: TokensMode,
    // Context menu state (for ContextMenu mode)
    pub context_menu_selection: usize,
    // Transfer mode state
    pub transfer_recipient: String,
    pub transfer_amount: String,
    pub transfer_field: TransferField,
    pub is_editing: bool,
    // Mint mode state
    pub mint_recipient: String,
    pub mint_amount: String,
    pub mint_field: TransferField,
    // Genesis mode state
    pub genesis_supply_cap: String,
    pub genesis_unlimited: bool,
    pub genesis_field: GenesisField,
    // Messages
    pub error_message: Option<String>,
    pub success_message: Option<String>,
}

impl TokensComponent {
    pub fn new(action_tx: UnboundedSender<Action>) -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            action_tx,
            account: None,
            balances: Vec::new(),
            ct_cells: Vec::new(),
            selected_index: 0,
            list_state,
            mode: TokensMode::List,
            context_menu_selection: 0,
            transfer_recipient: String::new(),
            transfer_amount: String::new(),
            transfer_field: TransferField::Recipient,
            is_editing: false,
            mint_recipient: String::new(),
            mint_amount: String::new(),
            mint_field: TransferField::Recipient,
            genesis_supply_cap: String::new(),
            genesis_unlimited: true,
            genesis_field: GenesisField::Unlimited,
            error_message: None,
            success_message: None,
        }
    }

    /// Set the current account.
    pub fn set_account(&mut self, account: Option<Account>) {
        self.account = account;
    }

    /// Set token balances.
    pub fn set_balances(&mut self, balances: Vec<CtBalance>) {
        self.balances = balances;
        // Total items = tokens + 1 ("Create New Token")
        let total_items = self.balances.len() + 1;
        if self.selected_index >= total_items {
            self.selected_index = total_items.saturating_sub(1);
        }
        self.list_state.select(Some(self.selected_index));
    }

    /// Set CT cells.
    pub fn set_ct_cells(&mut self, cells: Vec<CtCell>) {
        self.ct_cells = cells;
    }

    /// Get the currently selected token balance.
    pub fn selected_balance(&self) -> Option<&CtBalance> {
        self.balances.get(self.selected_index)
    }

    /// Clear transfer form.
    pub fn clear_transfer(&mut self) {
        self.transfer_recipient.clear();
        self.transfer_amount.clear();
        self.transfer_field = TransferField::Recipient;
        self.is_editing = false;
    }

    /// Clear mint form and pre-fill recipient with current account's stealth address.
    pub fn clear_mint(&mut self) {
        // Default to minting to self (current account's stealth address)
        self.mint_recipient = self
            .account
            .as_ref()
            .map(|acc| acc.stealth_address())
            .unwrap_or_default();
        self.mint_amount.clear();
        // Skip recipient field since it's pre-filled, start at amount
        self.mint_field = TransferField::Amount;
        self.is_editing = false;
    }

    /// Clear genesis form.
    pub fn clear_genesis(&mut self) {
        self.genesis_supply_cap.clear();
        self.genesis_unlimited = true;
        self.genesis_field = GenesisField::Unlimited;
        self.is_editing = false;
    }

    /// Request passphrase popup for signing a token transaction.
    pub fn start_passphrase_input(&mut self, purpose: PassphrasePurpose) {
        self.error_message = None;
        let _ = self.action_tx.send(Action::ShowPassphrasePopup(purpose));
    }

    /// Parse genesis supply cap to u128.
    pub fn parse_genesis_supply_cap(&self) -> Option<u128> {
        if self.genesis_unlimited {
            Some(0) // 0 means unlimited
        } else {
            parse_token_amount(&self.genesis_supply_cap).map(|v| v as u128)
        }
    }

    /// Parse transfer amount to u64.
    pub fn parse_transfer_amount(&self) -> Option<u64> {
        parse_token_amount(&self.transfer_amount)
    }

    /// Parse mint amount to u64.
    pub fn parse_mint_amount(&self) -> Option<u64> {
        parse_token_amount(&self.mint_amount)
    }

    /// Move to next item in the list.
    /// Total items = balances.len() + 1 (for "Create New Token").
    fn next_token(&mut self) {
        let total_items = self.balances.len() + 1;
        let i = if self.selected_index >= total_items - 1 {
            0
        } else {
            self.selected_index + 1
        };
        self.selected_index = i;
        self.list_state.select(Some(i));
    }

    /// Move to previous item in the list.
    /// Total items = balances.len() + 1 (for "Create New Token").
    fn prev_token(&mut self) {
        let total_items = self.balances.len() + 1;
        let i = if self.selected_index == 0 {
            total_items - 1
        } else {
            self.selected_index - 1
        };
        self.selected_index = i;
        self.list_state.select(Some(i));
    }

    /// Check if "Create New Token" item is selected.
    fn is_create_new_selected(&self) -> bool {
        self.selected_index == self.balances.len()
    }

    fn next_field(&mut self) {
        match self.mode {
            TokensMode::Transfer => {
                self.transfer_field = match self.transfer_field {
                    TransferField::Recipient => TransferField::Amount,
                    TransferField::Amount => TransferField::Confirm,
                    TransferField::Confirm => TransferField::Recipient,
                };
            }
            TokensMode::Mint => {
                self.mint_field = match self.mint_field {
                    TransferField::Recipient => TransferField::Amount,
                    TransferField::Amount => TransferField::Confirm,
                    TransferField::Confirm => TransferField::Recipient,
                };
            }
            TokensMode::Genesis => {
                self.genesis_field = match self.genesis_field {
                    GenesisField::Unlimited => GenesisField::SupplyCap,
                    GenesisField::SupplyCap => GenesisField::Confirm,
                    GenesisField::Confirm => GenesisField::Unlimited,
                };
            }
            TokensMode::List | TokensMode::ContextMenu => {}
        }
    }

    fn prev_field(&mut self) {
        match self.mode {
            TokensMode::Transfer => {
                self.transfer_field = match self.transfer_field {
                    TransferField::Recipient => TransferField::Confirm,
                    TransferField::Amount => TransferField::Recipient,
                    TransferField::Confirm => TransferField::Amount,
                };
            }
            TokensMode::Mint => {
                self.mint_field = match self.mint_field {
                    TransferField::Recipient => TransferField::Confirm,
                    TransferField::Amount => TransferField::Recipient,
                    TransferField::Confirm => TransferField::Amount,
                };
            }
            TokensMode::Genesis => {
                self.genesis_field = match self.genesis_field {
                    GenesisField::Unlimited => GenesisField::Confirm,
                    GenesisField::SupplyCap => GenesisField::Unlimited,
                    GenesisField::Confirm => GenesisField::SupplyCap,
                };
            }
            TokensMode::List | TokensMode::ContextMenu => {}
        }
    }

    fn handle_char(&mut self, c: char) {
        match self.mode {
            TokensMode::Transfer => match self.transfer_field {
                TransferField::Recipient => {
                    self.transfer_recipient.push(c);
                }
                TransferField::Amount => {
                    if c.is_ascii_digit() || (c == '.' && !self.transfer_amount.contains('.')) {
                        self.transfer_amount.push(c);
                    }
                }
                TransferField::Confirm => {}
            },
            TokensMode::Mint => match self.mint_field {
                TransferField::Recipient => {
                    self.mint_recipient.push(c);
                }
                TransferField::Amount => {
                    if c.is_ascii_digit() || (c == '.' && !self.mint_amount.contains('.')) {
                        self.mint_amount.push(c);
                    }
                }
                TransferField::Confirm => {}
            },
            TokensMode::Genesis => match self.genesis_field {
                GenesisField::SupplyCap => {
                    if c.is_ascii_digit() || (c == '.' && !self.genesis_supply_cap.contains('.')) {
                        self.genesis_supply_cap.push(c);
                    }
                }
                GenesisField::Unlimited | GenesisField::Confirm => {}
            },
            TokensMode::List | TokensMode::ContextMenu => {}
        }
    }

    fn handle_backspace(&mut self) {
        match self.mode {
            TokensMode::Transfer => match self.transfer_field {
                TransferField::Recipient => {
                    self.transfer_recipient.pop();
                }
                TransferField::Amount => {
                    self.transfer_amount.pop();
                }
                TransferField::Confirm => {}
            },
            TokensMode::Mint => match self.mint_field {
                TransferField::Recipient => {
                    self.mint_recipient.pop();
                }
                TransferField::Amount => {
                    self.mint_amount.pop();
                }
                TransferField::Confirm => {}
            },
            TokensMode::Genesis => match self.genesis_field {
                GenesisField::SupplyCap => {
                    self.genesis_supply_cap.pop();
                }
                GenesisField::Unlimited | GenesisField::Confirm => {}
            },
            TokensMode::List | TokensMode::ContextMenu => {}
        }
    }

    pub fn paste(&mut self, text: &str) {
        match self.mode {
            TokensMode::Transfer => match self.transfer_field {
                TransferField::Recipient => {
                    self.transfer_recipient.push_str(text);
                }
                TransferField::Amount => {
                    for c in text.chars() {
                        if c.is_ascii_digit() || (c == '.' && !self.transfer_amount.contains('.')) {
                            self.transfer_amount.push(c);
                        }
                    }
                }
                TransferField::Confirm => {}
            },
            TokensMode::Mint => match self.mint_field {
                TransferField::Recipient => {
                    self.mint_recipient.push_str(text);
                }
                TransferField::Amount => {
                    for c in text.chars() {
                        if c.is_ascii_digit() || (c == '.' && !self.mint_amount.contains('.')) {
                            self.mint_amount.push(c);
                        }
                    }
                }
                TransferField::Confirm => {}
            },
            TokensMode::Genesis => match self.genesis_field {
                GenesisField::SupplyCap => {
                    for c in text.chars() {
                        if c.is_ascii_digit()
                            || (c == '.' && !self.genesis_supply_cap.contains('.'))
                        {
                            self.genesis_supply_cap.push(c);
                        }
                    }
                }
                GenesisField::Unlimited | GenesisField::Confirm => {}
            },
            TokensMode::List | TokensMode::ContextMenu => {}
        }
    }

    /// Validate transfer inputs.
    pub fn validate_transfer(&self) -> Option<String> {
        if self.account.is_none() {
            return Some("No account selected".to_string());
        }

        if self.balances.is_empty() {
            return Some("No tokens to transfer".to_string());
        }

        let balance = self.selected_balance()?;

        if self.transfer_recipient.trim().is_empty() {
            return Some("Recipient address is required".to_string());
        }

        // Validate recipient format (should be 132 hex chars for stealth address)
        let recipient = self.transfer_recipient.trim().trim_start_matches("0x");
        if recipient.len() != 132 {
            return Some(format!(
                "Invalid stealth address length: {} (expected 132 hex chars)",
                recipient.len()
            ));
        }

        if hex::decode(recipient).is_err() {
            return Some("Invalid stealth address format (not valid hex)".to_string());
        }

        match self.parse_transfer_amount() {
            None => Some("Invalid amount format".to_string()),
            Some(0) => Some("Amount must be greater than 0".to_string()),
            Some(amount) => {
                if amount > balance.total_amount {
                    Some(format!(
                        "Insufficient balance: {} > {}",
                        format_token_amount(amount),
                        format_token_amount(balance.total_amount)
                    ))
                } else {
                    None
                }
            }
        }
    }

    /// Validate mint inputs.
    pub fn validate_mint(&self) -> Option<String> {
        if self.account.is_none() {
            return Some("No account selected".to_string());
        }

        if self.mint_recipient.trim().is_empty() {
            return Some("Recipient address is required".to_string());
        }

        // Validate recipient format
        let recipient = self.mint_recipient.trim().trim_start_matches("0x");
        if recipient.len() != 132 {
            return Some(format!(
                "Invalid stealth address length: {} (expected 132 hex chars)",
                recipient.len()
            ));
        }

        if hex::decode(recipient).is_err() {
            return Some("Invalid stealth address format (not valid hex)".to_string());
        }

        match self.parse_mint_amount() {
            None => Some("Invalid amount format".to_string()),
            Some(0) => Some("Amount must be greater than 0".to_string()),
            Some(_) => None,
        }
    }

    /// Validate genesis inputs.
    pub fn validate_genesis(&self) -> Option<String> {
        if self.account.is_none() {
            return Some("No account selected".to_string());
        }

        // If not unlimited, validate supply cap
        if !self.genesis_unlimited {
            if self.genesis_supply_cap.trim().is_empty() {
                return Some("Supply cap is required (or select Unlimited)".to_string());
            }
            if self.parse_genesis_supply_cap().is_none() {
                return Some("Invalid supply cap format".to_string());
            }
        }

        None
    }

    /// Static draw method for use in the main app draw loop.
    #[allow(clippy::too_many_arguments)]
    pub fn draw_static(
        f: &mut Frame,
        area: Rect,
        account: Option<&Account>,
        balances: &[CtBalance],
        selected_index: usize,
        mode: TokensMode,
        context_menu_selection: usize,
        transfer_recipient: &str,
        transfer_amount: &str,
        transfer_field: TransferField,
        mint_recipient: &str,
        mint_amount: &str,
        mint_field: TransferField,
        genesis_supply_cap: &str,
        genesis_unlimited: bool,
        genesis_field: GenesisField,
        _is_editing: bool,
        error_message: Option<&str>,
        success_message: Option<&str>,
    ) {
        match mode {
            TokensMode::List => {
                Self::draw_list_mode(f, area, account, balances, selected_index, error_message);
            }
            TokensMode::ContextMenu => {
                Self::draw_context_menu(
                    f,
                    area,
                    account,
                    balances,
                    selected_index,
                    context_menu_selection,
                    error_message,
                );
            }
            TokensMode::Transfer => {
                Self::draw_transfer_mode(
                    f,
                    area,
                    account,
                    balances.get(selected_index),
                    transfer_recipient,
                    transfer_amount,
                    transfer_field,
                    _is_editing,
                    error_message,
                    success_message,
                );
            }
            TokensMode::Mint => {
                Self::draw_mint_mode(
                    f,
                    area,
                    account,
                    mint_recipient,
                    mint_amount,
                    mint_field,
                    _is_editing,
                    error_message,
                    success_message,
                );
            }
            TokensMode::Genesis => {
                Self::draw_genesis_mode(
                    f,
                    area,
                    account,
                    genesis_supply_cap,
                    genesis_unlimited,
                    genesis_field,
                    _is_editing,
                    error_message,
                    success_message,
                );
            }
        }
    }

    fn draw_list_mode(
        f: &mut Frame,
        area: Rect,
        account: Option<&Account>,
        balances: &[CtBalance],
        selected_index: usize,
        error_message: Option<&str>,
    ) {
        let chunks = Layout::horizontal([Constraint::Length(40), Constraint::Min(0)]).split(area);

        // Left side: Token list (no longer split for Operations panel)
        let left_chunks =
            Layout::vertical([Constraint::Min(0), Constraint::Length(3)]).split(chunks[0]);

        // Build list items: tokens + "Create New Token"
        let mut items: Vec<ListItem> = balances
            .iter()
            .enumerate()
            .map(|(i, bal)| {
                let style = if i == selected_index {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Reset)
                };

                let amount_str = format_token_amount(bal.total_amount);
                let cell_count = format!(
                    "({} cell{})",
                    bal.cell_count,
                    if bal.cell_count == 1 { "" } else { "s" }
                );
                let content = Line::from(vec![
                    Span::styled(bal.display_name(), style),
                    Span::raw("  "),
                    Span::styled(amount_str, Style::default().fg(Color::Green)),
                    Span::raw("  "),
                    Span::styled(cell_count, Style::default().fg(Color::DarkGray)),
                ]);
                ListItem::new(content)
            })
            .collect();

        // Add "Create New Token" as the last item
        let create_new_index = balances.len();
        let create_new_style = if selected_index == create_new_index {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Yellow)
        };
        items.push(ListItem::new(Line::from(vec![Span::styled(
            "+ Create New Token",
            create_new_style,
        )])));

        let mut list_state = ListState::default();
        list_state.select(Some(selected_index));

        let account_name = account.map(|a| a.name.as_str()).unwrap_or("None");

        let list = List::new(items)
            .block(
                Block::default()
                    .title(format!("Token Balances - {}", account_name))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        f.render_stateful_widget(list, left_chunks[0], &mut list_state);

        // Help text at bottom of left panel
        let help_text = Line::from(Span::styled(
            "Up/Down: Navigate | Enter: Select",
            Style::default().fg(Color::DarkGray),
        ));
        let help_widget = Paragraph::new(help_text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(help_widget, left_chunks[1]);

        // Right side: Token details
        let right_chunks =
            Layout::vertical([Constraint::Min(0), Constraint::Length(3)]).split(chunks[1]);

        let details = if selected_index < balances.len() {
            // Show selected token details
            let bal = &balances[selected_index];
            vec![
                Line::from(vec![Span::styled(
                    "Token ID: ",
                    Style::default().fg(Color::DarkGray),
                )]),
                Line::from(vec![Span::styled(
                    hex::encode(bal.token_id),
                    Style::default().fg(Color::Yellow),
                )]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Balance: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format_token_amount(bal.total_amount),
                        Style::default().fg(Color::Green),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Cells: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        bal.cell_count.to_string(),
                        Style::default().fg(Color::Reset),
                    ),
                ]),
            ]
        } else {
            // "Create New Token" is selected
            vec![
                Line::from(vec![Span::styled(
                    "Create New Token",
                    Style::default().fg(Color::Yellow),
                )]),
                Line::from(""),
                Line::from("Press Enter to create a new CT token."),
                Line::from("You will become the issuer of this token."),
            ]
        };

        let details_widget = Paragraph::new(details).block(
            Block::default()
                .title("Token Details")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

        f.render_widget(details_widget, right_chunks[0]);

        // Status/error message
        let status_text = if let Some(err) = error_message {
            Line::from(Span::styled(err, Style::default().fg(Color::Red)))
        } else {
            Line::from(Span::styled(
                "Enter: Open menu / Create token",
                Style::default().fg(Color::DarkGray),
            ))
        };

        let status_widget = Paragraph::new(status_text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

        f.render_widget(status_widget, right_chunks[1]);
    }

    /// Draw context menu overlay for token operations (Transfer/Mint).
    fn draw_context_menu(
        f: &mut Frame,
        area: Rect,
        account: Option<&Account>,
        balances: &[CtBalance],
        selected_index: usize,
        context_menu_selection: usize,
        error_message: Option<&str>,
    ) {
        // First draw the list mode as background
        Self::draw_list_mode(f, area, account, balances, selected_index, error_message);

        // Calculate popup position (centered, small size)
        let popup_width = 20u16;
        let popup_height = 6u16;
        let popup_x = area.x + (area.width.saturating_sub(popup_width)) / 2;
        let popup_y = area.y + (area.height.saturating_sub(popup_height)) / 2;

        let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

        // Clear background for popup
        let clear = Block::default().style(Style::default().bg(Color::Reset));
        f.render_widget(clear, popup_area);

        // Build menu items
        let ops = ContextMenuOperation::all();
        let menu_items: Vec<ListItem> = ops
            .iter()
            .enumerate()
            .map(|(i, op)| {
                let style = if i == context_menu_selection {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Reset)
                };
                ListItem::new(Line::from(Span::styled(
                    format!("  {}  ", op.label()),
                    style,
                )))
            })
            .collect();

        let mut menu_state = ListState::default();
        menu_state.select(Some(context_menu_selection));

        let menu = List::new(menu_items).block(
            Block::default()
                .title("Select Action")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

        f.render_stateful_widget(menu, popup_area, &mut menu_state);
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_transfer_mode(
        f: &mut Frame,
        area: Rect,
        account: Option<&Account>,
        selected_balance: Option<&CtBalance>,
        recipient: &str,
        amount: &str,
        focused_field: TransferField,
        _is_editing: bool,
        error_message: Option<&str>,
        success_message: Option<&str>,
    ) {
        let chunks = Layout::vertical([
            Constraint::Length(5), // Token/Account info
            Constraint::Length(5), // Recipient
            Constraint::Length(5), // Amount
            Constraint::Length(5), // Confirm button
            Constraint::Min(0),    // Status/help
        ])
        .split(area);

        // Token/Account info
        let info = if let (Some(acc), Some(bal)) = (account, selected_balance) {
            vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("From: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&acc.name, Style::default().fg(Color::Reset)),
                    Span::raw("  |  "),
                    Span::styled("Token: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(bal.display_name(), Style::default().fg(Color::Cyan)),
                    Span::raw("  |  "),
                    Span::styled("Available: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format_token_amount(bal.total_amount),
                        Style::default().fg(Color::Green),
                    ),
                ]),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "No account or token selected",
                    Style::default().fg(Color::Red),
                )]),
            ]
        };

        let info_widget = Paragraph::new(info).block(
            Block::default()
                .title("Transfer CT Token [Esc] Back")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
        f.render_widget(info_widget, chunks[0]);

        // Recipient input - always show cursor when focused (direct input mode)
        let recipient_style = if focused_field == TransferField::Recipient {
            Style::default().fg(Color::Yellow) // Always "editing" style when focused
        } else {
            Style::default().fg(Color::Reset)
        };

        let recipient_text = if recipient.is_empty() && focused_field != TransferField::Recipient {
            "Enter stealth address (132 hex chars)"
        } else if recipient.is_empty() {
            "|"
        } else {
            recipient
        };

        let mut recipient_display = recipient_text.to_string();
        if focused_field == TransferField::Recipient && !recipient.is_empty() {
            recipient_display.push('|');
        }

        let recipient_widget = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled(recipient_display, recipient_style)]),
        ])
        .block(
            Block::default()
                .title(if focused_field == TransferField::Recipient {
                    "> Recipient Stealth Address"
                } else {
                    "  Recipient Stealth Address"
                })
                .borders(Borders::ALL)
                .border_style(if focused_field == TransferField::Recipient {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        );
        f.render_widget(recipient_widget, chunks[1]);

        // Amount input - always show cursor when focused (direct input mode)
        let amount_style = if focused_field == TransferField::Amount {
            Style::default().fg(Color::Yellow) // Always "editing" style when focused
        } else {
            Style::default().fg(Color::Reset)
        };

        let amount_text = if amount.is_empty() && focused_field != TransferField::Amount {
            "Enter token amount"
        } else if amount.is_empty() {
            "|"
        } else {
            amount
        };

        let mut amount_display = amount_text.to_string();
        if focused_field == TransferField::Amount && !amount.is_empty() {
            amount_display.push('|');
        }

        let amount_widget = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled(amount_display, amount_style)]),
        ])
        .block(
            Block::default()
                .title(if focused_field == TransferField::Amount {
                    "> Amount"
                } else {
                    "  Amount"
                })
                .borders(Borders::ALL)
                .border_style(if focused_field == TransferField::Amount {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        );
        f.render_widget(amount_widget, chunks[2]);

        // Confirm button
        let confirm_style = if focused_field == TransferField::Confirm {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Green)
        };

        let confirm_widget = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled("  [ Transfer Tokens ]  ", confirm_style)]),
        ])
        .block(
            Block::default()
                .title(if focused_field == TransferField::Confirm {
                    "> Confirm"
                } else {
                    "  Confirm"
                })
                .borders(Borders::ALL)
                .border_style(if focused_field == TransferField::Confirm {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        );
        f.render_widget(confirm_widget, chunks[3]);

        // Status/help
        let mut status_lines = vec![Line::from("")];

        if let Some(err) = error_message {
            status_lines.push(Line::from(vec![Span::styled(
                format!("Error: {}", err),
                Style::default().fg(Color::Red),
            )]));
        } else if let Some(success) = success_message {
            status_lines.push(Line::from(vec![Span::styled(
                success,
                Style::default().fg(Color::Green),
            )]));
        }

        status_lines.push(Line::from(""));
        status_lines.push(Line::from(vec![Span::styled(
            "Up/Down: Navigate | Enter: Edit/Confirm | ESC: Back",
            Style::default().fg(Color::DarkGray),
        )]));

        let status_widget = Paragraph::new(status_lines).block(
            Block::default()
                .title("Help")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(status_widget, chunks[4]);
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_mint_mode(
        f: &mut Frame,
        area: Rect,
        account: Option<&Account>,
        recipient: &str,
        amount: &str,
        focused_field: TransferField,
        _is_editing: bool,
        error_message: Option<&str>,
        success_message: Option<&str>,
    ) {
        let chunks = Layout::vertical([
            Constraint::Length(5), // Account info
            Constraint::Length(5), // Recipient
            Constraint::Length(5), // Amount
            Constraint::Length(5), // Confirm button
            Constraint::Min(0),    // Status/help
        ])
        .split(area);

        // Account info
        let info = if let Some(acc) = account {
            vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("Issuer: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&acc.name, Style::default().fg(Color::Reset)),
                    Span::raw("  |  "),
                    Span::styled("Minting new CT tokens", Style::default().fg(Color::Magenta)),
                ]),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "No account selected",
                    Style::default().fg(Color::Red),
                )]),
            ]
        };

        let info_widget = Paragraph::new(info).block(
            Block::default()
                .title("Mint CT Token [Esc] Back")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta)),
        );
        f.render_widget(info_widget, chunks[0]);

        // Recipient input - always show cursor when focused (direct input mode)
        let recipient_style = if focused_field == TransferField::Recipient {
            Style::default().fg(Color::Yellow) // Always "editing" style when focused
        } else {
            Style::default().fg(Color::Reset)
        };

        let recipient_text = if recipient.is_empty() && focused_field != TransferField::Recipient {
            "Enter recipient stealth address (132 hex chars)"
        } else if recipient.is_empty() {
            "|"
        } else {
            recipient
        };

        let mut recipient_display = recipient_text.to_string();
        if focused_field == TransferField::Recipient && !recipient.is_empty() {
            recipient_display.push('|');
        }

        let recipient_widget = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled(recipient_display, recipient_style)]),
        ])
        .block(
            Block::default()
                .title(if focused_field == TransferField::Recipient {
                    "> Recipient (default: self)"
                } else {
                    "  Recipient (default: self)"
                })
                .borders(Borders::ALL)
                .border_style(if focused_field == TransferField::Recipient {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        );
        f.render_widget(recipient_widget, chunks[1]);

        // Amount input - always show cursor when focused (direct input mode)
        let amount_style = if focused_field == TransferField::Amount {
            Style::default().fg(Color::Yellow) // Always "editing" style when focused
        } else {
            Style::default().fg(Color::Reset)
        };

        let amount_text = if amount.is_empty() && focused_field != TransferField::Amount {
            "Enter amount to mint"
        } else if amount.is_empty() {
            "|"
        } else {
            amount
        };

        let mut amount_display = amount_text.to_string();
        if focused_field == TransferField::Amount && !amount.is_empty() {
            amount_display.push('|');
        }

        let amount_widget = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled(amount_display, amount_style)]),
        ])
        .block(
            Block::default()
                .title(if focused_field == TransferField::Amount {
                    "> Amount"
                } else {
                    "  Amount"
                })
                .borders(Borders::ALL)
                .border_style(if focused_field == TransferField::Amount {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        );
        f.render_widget(amount_widget, chunks[2]);

        // Confirm button
        let confirm_style = if focused_field == TransferField::Confirm {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Magenta)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Magenta)
        };

        let confirm_widget = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled("  [ Mint Tokens ]  ", confirm_style)]),
        ])
        .block(
            Block::default()
                .title(if focused_field == TransferField::Confirm {
                    "> Confirm"
                } else {
                    "  Confirm"
                })
                .borders(Borders::ALL)
                .border_style(if focused_field == TransferField::Confirm {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        );
        f.render_widget(confirm_widget, chunks[3]);

        // Status/help
        let mut status_lines = vec![Line::from("")];

        if let Some(err) = error_message {
            status_lines.push(Line::from(vec![Span::styled(
                format!("Error: {}", err),
                Style::default().fg(Color::Red),
            )]));
        } else if let Some(success) = success_message {
            status_lines.push(Line::from(vec![Span::styled(
                success,
                Style::default().fg(Color::Green),
            )]));
        }

        status_lines.push(Line::from(""));
        status_lines.push(Line::from(vec![Span::styled(
            "Up/Down: Navigate | Enter: Edit/Confirm | ESC: Back",
            Style::default().fg(Color::DarkGray),
        )]));

        let status_widget = Paragraph::new(status_lines).block(
            Block::default()
                .title("Help")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(status_widget, chunks[4]);
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_genesis_mode(
        f: &mut Frame,
        area: Rect,
        account: Option<&Account>,
        supply_cap: &str,
        unlimited: bool,
        focused_field: GenesisField,
        _is_editing: bool,
        error_message: Option<&str>,
        success_message: Option<&str>,
    ) {
        let chunks = Layout::vertical([
            Constraint::Length(5), // Account info
            Constraint::Length(3), // Options (Unlimited checkbox)
            Constraint::Length(5), // Supply cap
            Constraint::Length(5), // Confirm button
            Constraint::Min(0),    // Status/help
        ])
        .split(area);

        // Account info
        let info = if let Some(acc) = account {
            vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("Issuer: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&acc.name, Style::default().fg(Color::Reset)),
                    Span::raw("  |  "),
                    Span::styled(
                        "Creating new CT token (genesis)",
                        Style::default().fg(Color::Yellow),
                    ),
                ]),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "No account selected",
                    Style::default().fg(Color::Red),
                )]),
            ]
        };

        let info_widget = Paragraph::new(info).block(
            Block::default()
                .title("Create New Token [Esc] Back")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        );
        f.render_widget(info_widget, chunks[0]);

        // Options (Unlimited checkbox) - now in chunks[1]
        let checkbox_style = if focused_field == GenesisField::Unlimited {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::Reset)
        };

        let checkbox_text = if unlimited {
            "[x] Unlimited"
        } else {
            "[ ] Unlimited"
        };

        let checkbox_widget = Paragraph::new(vec![Line::from(vec![Span::styled(
            checkbox_text,
            checkbox_style,
        )])])
        .block(
            Block::default()
                .title(if focused_field == GenesisField::Unlimited {
                    "> Options"
                } else {
                    "  Options"
                })
                .borders(Borders::ALL)
                .border_style(if focused_field == GenesisField::Unlimited {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        );
        f.render_widget(checkbox_widget, chunks[1]);

        // Supply cap input - now in chunks[2]
        let supply_style = if focused_field == GenesisField::SupplyCap {
            if unlimited {
                Style::default().fg(Color::DarkGray) // Disabled when unlimited is checked
            } else {
                Style::default().fg(Color::Yellow) // Always "editing" style when focused and not unlimited
            }
        } else if unlimited {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::Reset)
        };

        let supply_text = if unlimited {
            "Unlimited (checkbox enabled)".to_string()
        } else if supply_cap.is_empty() && focused_field != GenesisField::SupplyCap {
            "Enter maximum supply".to_string()
        } else if supply_cap.is_empty() {
            "|".to_string()
        } else {
            supply_cap.to_string()
        };

        let mut supply_display = supply_text;
        if focused_field == GenesisField::SupplyCap && !unlimited && !supply_cap.is_empty() {
            supply_display.push('|');
        }

        let supply_widget = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled(supply_display, supply_style)]),
        ])
        .block(
            Block::default()
                .title(if focused_field == GenesisField::SupplyCap {
                    "> Supply Cap"
                } else {
                    "  Supply Cap"
                })
                .borders(Borders::ALL)
                .border_style(if focused_field == GenesisField::SupplyCap {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        );
        f.render_widget(supply_widget, chunks[2]);

        // Confirm button
        let confirm_style = if focused_field == GenesisField::Confirm {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Yellow)
        };

        let confirm_widget = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled("  [ Create Token ]  ", confirm_style)]),
        ])
        .block(
            Block::default()
                .title(if focused_field == GenesisField::Confirm {
                    "> Confirm"
                } else {
                    "  Confirm"
                })
                .borders(Borders::ALL)
                .border_style(if focused_field == GenesisField::Confirm {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        );
        f.render_widget(confirm_widget, chunks[3]);

        // Status/help
        let mut status_lines = vec![Line::from("")];

        if let Some(err) = error_message {
            status_lines.push(Line::from(vec![Span::styled(
                format!("Error: {}", err),
                Style::default().fg(Color::Red),
            )]));
        } else if let Some(success) = success_message {
            status_lines.push(Line::from(vec![Span::styled(
                success,
                Style::default().fg(Color::Green),
            )]));
        }

        status_lines.push(Line::from(""));
        status_lines.push(Line::from(vec![Span::styled(
            if focused_field == GenesisField::Unlimited {
                "Space/Enter: Toggle | Up/Down: Navigate | ESC: Back"
            } else {
                "Up/Down: Navigate | Enter: Edit/Confirm | ESC: Back"
            },
            Style::default().fg(Color::DarkGray),
        )]));

        let status_widget = Paragraph::new(status_lines).block(
            Block::default()
                .title("Help")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(status_widget, chunks[4]);
    }

    /// Check if we're on an input field that needs direct character input.
    pub fn needs_direct_input(&self) -> bool {
        match self.mode {
            TokensMode::List | TokensMode::ContextMenu => false,
            TokensMode::Transfer => matches!(
                self.transfer_field,
                TransferField::Recipient | TransferField::Amount
            ),
            TokensMode::Mint => matches!(
                self.mint_field,
                TransferField::Recipient | TransferField::Amount
            ),
            TokensMode::Genesis => {
                self.genesis_field == GenesisField::SupplyCap && !self.genesis_unlimited
            }
        }
    }

    /// Check if actively editing (typing input).
    pub fn is_editing(&self) -> bool {
        self.is_editing
    }
}

impl Component for TokensComponent {
    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        // Clear previous messages on any input
        self.error_message = None;

        match self.mode {
            TokensMode::List => {
                match key.code {
                    KeyCode::Down => {
                        self.next_token();
                    }
                    KeyCode::Up => {
                        self.prev_token();
                    }
                    KeyCode::Enter => {
                        if self.is_create_new_selected() {
                            // "Create New Token" selected - go directly to Genesis mode
                            self.mode = TokensMode::Genesis;
                            self.clear_genesis();
                        } else if !self.balances.is_empty() {
                            // Token selected - show context menu
                            self.mode = TokensMode::ContextMenu;
                            self.context_menu_selection = 0;
                        }
                    }
                    _ => {}
                }
            }
            TokensMode::ContextMenu => {
                let ops = ContextMenuOperation::all();
                match key.code {
                    KeyCode::Down => {
                        if self.context_menu_selection >= ops.len() - 1 {
                            self.context_menu_selection = 0;
                        } else {
                            self.context_menu_selection += 1;
                        }
                    }
                    KeyCode::Up => {
                        if self.context_menu_selection == 0 {
                            self.context_menu_selection = ops.len() - 1;
                        } else {
                            self.context_menu_selection -= 1;
                        }
                    }
                    KeyCode::Enter => {
                        if let Some(op) = ops.get(self.context_menu_selection) {
                            match op {
                                ContextMenuOperation::Transfer => {
                                    self.mode = TokensMode::Transfer;
                                    self.clear_transfer();
                                }
                                ContextMenuOperation::Mint => {
                                    self.mode = TokensMode::Mint;
                                    self.clear_mint();
                                }
                            }
                        }
                    }
                    KeyCode::Esc => {
                        // Return to list mode
                        self.mode = TokensMode::List;
                    }
                    _ => {}
                }
            }
            TokensMode::Transfer | TokensMode::Mint | TokensMode::Genesis => {
                // Check if we're on an input field (Recipient or Amount)
                let on_input_field = self.needs_direct_input();

                if self.is_editing && on_input_field {
                    // Editing mode - process characters
                    match key.code {
                        KeyCode::Esc => {
                            // Exit editing mode
                            self.is_editing = false;
                        }
                        KeyCode::Char(c) => {
                            self.handle_char(c);
                        }
                        KeyCode::Backspace => {
                            self.handle_backspace();
                        }
                        KeyCode::Enter => {
                            // Exit editing and move to next field
                            self.next_field();
                            // Auto-enter edit mode if next field is also an input field
                            self.is_editing = self.needs_direct_input();
                        }
                        KeyCode::Down => {
                            // Move to next field while editing
                            self.next_field();
                            // Auto-enter edit mode if next field is also an input field
                            self.is_editing = self.needs_direct_input();
                        }
                        KeyCode::Up => {
                            // Move to previous field while editing
                            self.prev_field();
                            // Auto-enter edit mode if previous field is also an input field
                            self.is_editing = self.needs_direct_input();
                        }
                        _ => {}
                    }
                } else {
                    // Navigation mode - handle field switching and actions
                    match key.code {
                        KeyCode::Esc => {
                            // Return to list mode
                            self.mode = TokensMode::List;
                        }
                        KeyCode::Down => {
                            self.next_field();
                            // Auto-enter edit mode when selecting an input field
                            self.is_editing = self.needs_direct_input();
                        }
                        KeyCode::Up => {
                            self.prev_field();
                            // Auto-enter edit mode when selecting an input field
                            self.is_editing = self.needs_direct_input();
                        }
                        KeyCode::Char(' ') if self.mode == TokensMode::Genesis => {
                            // Toggle unlimited checkbox in Genesis mode
                            if self.genesis_field == GenesisField::Unlimited {
                                self.genesis_unlimited = !self.genesis_unlimited;
                            }
                        }
                        KeyCode::Enter => {
                            // On input field - start editing
                            if on_input_field {
                                self.is_editing = true;
                                return Ok(());
                            }

                            // Handle unlimited toggle on Enter in Genesis mode
                            if self.mode == TokensMode::Genesis
                                && self.genesis_field == GenesisField::Unlimited
                            {
                                self.genesis_unlimited = !self.genesis_unlimited;
                                return Ok(());
                            }

                            let is_confirm = match self.mode {
                                TokensMode::Transfer => {
                                    self.transfer_field == TransferField::Confirm
                                }
                                TokensMode::Mint => self.mint_field == TransferField::Confirm,
                                TokensMode::Genesis => self.genesis_field == GenesisField::Confirm,
                                TokensMode::List | TokensMode::ContextMenu => false,
                            };

                            if is_confirm {
                                // Validate and execute
                                let validation_error = match self.mode {
                                    TokensMode::Transfer => self.validate_transfer(),
                                    TokensMode::Mint => self.validate_mint(),
                                    TokensMode::Genesis => self.validate_genesis(),
                                    TokensMode::List | TokensMode::ContextMenu => None,
                                };

                                if let Some(err) = validation_error {
                                    self.error_message = Some(err);
                                } else {
                                    // Start passphrase input instead of directly sending
                                    match self.mode {
                                        TokensMode::Transfer => {
                                            self.start_passphrase_input(
                                                PassphrasePurpose::TransferToken,
                                            );
                                        }
                                        TokensMode::Mint => {
                                            self.start_passphrase_input(
                                                PassphrasePurpose::MintToken,
                                            );
                                        }
                                        TokensMode::Genesis => {
                                            self.start_passphrase_input(
                                                PassphrasePurpose::CreateToken,
                                            );
                                        }
                                        TokensMode::List | TokensMode::ContextMenu => {}
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame, area: Rect) {
        Self::draw_static(
            f,
            area,
            self.account.as_ref(),
            &self.balances,
            self.selected_index,
            self.mode,
            self.context_menu_selection,
            &self.transfer_recipient,
            &self.transfer_amount,
            self.transfer_field,
            &self.mint_recipient,
            &self.mint_amount,
            self.mint_field,
            &self.genesis_supply_cap,
            self.genesis_unlimited,
            self.genesis_field,
            self.is_editing,
            self.error_message.as_deref(),
            self.success_message.as_deref(),
        );
    }
}

/// Parse token amount string to u64.
/// CT tokens are whole numbers without decimals (unlike CKB which has 8 decimal places).
fn parse_token_amount(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // CT tokens are whole numbers, no decimals allowed
    s.parse().ok()
}

/// Format token amount for display.
/// CT tokens are whole numbers without decimals.
fn format_token_amount(amount: u64) -> String {
    amount.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that token amounts are parsed as integers, not with 8 decimal places.
    ///
    /// This is a regression test for the bug where `parse_token_amount("10000")`
    /// returned `1000000000000` (10000 * 10^8) instead of `10000`.
    ///
    /// The bug caused minting to fail with InvalidRangeProof because the amount
    /// exceeded the 32-bit range proof limit (4,294,967,295).
    #[test]
    fn test_token_amount_parsing_is_integer() {
        // Test various amount inputs
        let test_cases = vec![
            ("10000", Some(10000u64)),
            ("1", Some(1u64)),
            ("100", Some(100u64)),
            ("4294967295", Some(4294967295u64)), // Max 32-bit value
            ("0", Some(0u64)),
            ("", None),
            ("abc", None),
            ("10.5", None),            // Decimals not allowed for CT tokens
            ("  123  ", Some(123u64)), // Whitespace should be trimmed
        ];

        for (input, expected) in test_cases {
            let result = parse_token_amount(input);
            assert_eq!(
                result, expected,
                "parse_token_amount({:?}) should return {:?}, got {:?}",
                input, expected, result
            );
        }

        // Critical test: 10000 should NOT become 1000000000000
        let amount = parse_token_amount("10000").unwrap();
        assert!(
            amount <= u32::MAX as u64,
            "Amount {} should be within 32-bit range (max {}). \
             If this fails, token amounts are being multiplied by 10^8!",
            amount,
            u32::MAX
        );
    }

    #[test]
    fn test_format_token_amount_is_integer() {
        // Format should not add decimal places
        assert_eq!(format_token_amount(10000), "10000");
        assert_eq!(format_token_amount(1), "1");
        assert_eq!(format_token_amount(0), "0");
        assert_eq!(format_token_amount(4294967295), "4294967295");
    }
}
