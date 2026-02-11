use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{action::Action, tui::Frame};

use super::Component;

/// Available network options
const NETWORKS: [(&str, &str, &str); 3] = [
    ("testnet", "CKB Testnet", "https://testnet.ckb.dev"),
    ("mainnet", "CKB Mainnet", "https://mainnet.ckb.dev"),
    ("devnet", "Local Devnet", "http://127.0.0.1:8114"),
];

/// Settings menu sections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsSection {
    Wallet,
    Network,
}

/// Wallet operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletOperation {
    CreateAccount,
    ExportBackup,
}

impl WalletOperation {
    fn all() -> &'static [WalletOperation] {
        &[
            WalletOperation::CreateAccount,
            WalletOperation::ExportBackup,
        ]
    }

    fn label(&self) -> &'static str {
        match self {
            WalletOperation::CreateAccount => "Create New Account",
            WalletOperation::ExportBackup => "Export Wallet Backup",
        }
    }
}

/// Settings mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsMode {
    /// Normal menu navigation
    Menu,
    /// Entering passphrase for export
    EnteringPassphrase,
    /// Showing backup string
    ShowingBackup,
}

pub struct SettingsComponent {
    action_tx: UnboundedSender<Action>,
    pub current_network: String,
    pub mode: SettingsMode,
    pub section: SettingsSection,
    pub wallet_index: usize,
    pub network_index: usize,
    /// Backup string to display
    pub backup_string: Option<String>,
    /// Error message
    pub error_message: Option<String>,
    /// Success message
    pub success_message: Option<String>,
    /// Passphrase input for export
    pub passphrase_input: String,
}

impl SettingsComponent {
    pub fn new(action_tx: UnboundedSender<Action>, current_network: &str) -> Self {
        // Find index of current network
        let network_index = NETWORKS
            .iter()
            .position(|(name, _, _)| *name == current_network)
            .unwrap_or(0);

        Self {
            action_tx,
            current_network: current_network.to_string(),
            mode: SettingsMode::Menu,
            section: SettingsSection::Wallet,
            wallet_index: 0,
            network_index,
            backup_string: None,
            error_message: None,
            success_message: None,
            passphrase_input: String::new(),
        }
    }

    pub fn set_network(&mut self, network: &str) {
        self.current_network = network.to_string();
        self.network_index = NETWORKS
            .iter()
            .position(|(name, _, _)| *name == network)
            .unwrap_or(0);
    }

    pub fn set_backup_string(&mut self, backup: String) {
        self.backup_string = Some(backup);
        self.mode = SettingsMode::ShowingBackup;
    }

    pub fn start_passphrase_input(&mut self) {
        self.passphrase_input.clear();
        self.error_message = None;
        self.mode = SettingsMode::EnteringPassphrase;
    }

    pub fn get_passphrase(&self) -> &str {
        &self.passphrase_input
    }

    fn next_item(&mut self) {
        match self.section {
            SettingsSection::Wallet => {
                let ops = WalletOperation::all();
                if self.wallet_index >= ops.len() - 1 {
                    // Move to Network section
                    self.section = SettingsSection::Network;
                    self.network_index = 0;
                } else {
                    self.wallet_index += 1;
                }
            }
            SettingsSection::Network => {
                if self.network_index >= NETWORKS.len() - 1 {
                    // Wrap to Wallet section
                    self.section = SettingsSection::Wallet;
                    self.wallet_index = 0;
                } else {
                    self.network_index += 1;
                }
            }
        }
    }

    fn previous_item(&mut self) {
        match self.section {
            SettingsSection::Wallet => {
                if self.wallet_index == 0 {
                    // Wrap to Network section (last item)
                    self.section = SettingsSection::Network;
                    self.network_index = NETWORKS.len() - 1;
                } else {
                    self.wallet_index -= 1;
                }
            }
            SettingsSection::Network => {
                if self.network_index == 0 {
                    // Move to Wallet section (last item)
                    self.section = SettingsSection::Wallet;
                    self.wallet_index = WalletOperation::all().len() - 1;
                } else {
                    self.network_index -= 1;
                }
            }
        }
    }

    fn select_current(&mut self) -> Result<()> {
        match self.section {
            SettingsSection::Wallet => {
                let ops = WalletOperation::all();
                match ops[self.wallet_index] {
                    WalletOperation::CreateAccount => {
                        self.action_tx.send(Action::CreateAccount)?;
                    }
                    WalletOperation::ExportBackup => {
                        // Start passphrase input mode
                        self.start_passphrase_input();
                    }
                }
            }
            SettingsSection::Network => {
                let (name, _, _) = NETWORKS[self.network_index];
                if name != self.current_network {
                    self.action_tx
                        .send(Action::SwitchNetwork(name.to_string()))?;
                }
            }
        }
        Ok(())
    }

    /// Static draw method for use in App's draw_ui
    pub fn draw_static(
        f: &mut Frame,
        area: Rect,
        current_network: &str,
        mode: SettingsMode,
        section: SettingsSection,
        wallet_index: usize,
        network_index: usize,
        backup_string: Option<&str>,
        error_message: Option<&str>,
        success_message: Option<&str>,
        passphrase_input: &str,
    ) {
        // Show backup string overlay if in ShowingBackup mode
        if mode == SettingsMode::ShowingBackup {
            Self::draw_backup_overlay(f, area, backup_string);
            return;
        }

        // Show passphrase input overlay if in EnteringPassphrase mode
        if mode == SettingsMode::EnteringPassphrase {
            Self::draw_passphrase_overlay(f, area, passphrase_input, error_message);
            return;
        }

        let chunks = Layout::horizontal([Constraint::Length(40), Constraint::Min(0)]).split(area);

        // Left panel: Menu items
        let left_chunks = Layout::vertical([
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Min(0),
        ])
        .split(chunks[0]);

        // Wallet section
        let wallet_ops = WalletOperation::all();
        let wallet_items: Vec<ListItem> = wallet_ops
            .iter()
            .enumerate()
            .map(|(i, op)| {
                let is_selected = section == SettingsSection::Wallet && i == wallet_index;
                let style = if is_selected {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(Line::from(Span::styled(op.label(), style)))
            })
            .collect();

        let mut wallet_list_state = ListState::default();
        if section == SettingsSection::Wallet {
            wallet_list_state.select(Some(wallet_index));
        }

        let wallet_border_color = if section == SettingsSection::Wallet {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let wallet_list = List::new(wallet_items)
            .block(
                Block::default()
                    .title("Wallet")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(wallet_border_color)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        f.render_stateful_widget(wallet_list, left_chunks[0], &mut wallet_list_state);

        // Network section
        let network_items: Vec<ListItem> = NETWORKS
            .iter()
            .enumerate()
            .map(|(i, (name, display_name, _url))| {
                let is_current = *name == current_network;
                let is_selected = section == SettingsSection::Network && i == network_index;

                let style = if is_selected {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else if is_current {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::White)
                };

                let marker = if is_current { " [active]" } else { "" };
                ListItem::new(Line::from(Span::styled(
                    format!("{}{}", display_name, marker),
                    style,
                )))
            })
            .collect();

        let mut network_list_state = ListState::default();
        if section == SettingsSection::Network {
            network_list_state.select(Some(network_index));
        }

        let network_border_color = if section == SettingsSection::Network {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let network_list = List::new(network_items)
            .block(
                Block::default()
                    .title("Network")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(network_border_color)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        f.render_stateful_widget(network_list, left_chunks[1], &mut network_list_state);

        // Right panel: Details
        let mut details = vec![];

        match section {
            SettingsSection::Wallet => {
                let ops = WalletOperation::all();
                match ops[wallet_index] {
                    WalletOperation::CreateAccount => {
                        details.push(Line::from(vec![Span::styled(
                            "Create New Account",
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        )]));
                        details.push(Line::from(""));
                        details.push(Line::from(vec![Span::styled(
                            "Creates a new account derived from your",
                            Style::default().fg(Color::Gray),
                        )]));
                        details.push(Line::from(vec![Span::styled(
                            "wallet seed. Each account has unique",
                            Style::default().fg(Color::Gray),
                        )]));
                        details.push(Line::from(vec![Span::styled(
                            "stealth addresses for privacy.",
                            Style::default().fg(Color::Gray),
                        )]));
                        details.push(Line::from(""));
                        details.push(Line::from(vec![Span::styled(
                            "[Enter] Create account",
                            Style::default().fg(Color::DarkGray),
                        )]));
                    }
                    WalletOperation::ExportBackup => {
                        details.push(Line::from(vec![Span::styled(
                            "Export Wallet Backup",
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        )]));
                        details.push(Line::from(""));
                        details.push(Line::from(vec![Span::styled(
                            "Exports an encrypted backup string that",
                            Style::default().fg(Color::Gray),
                        )]));
                        details.push(Line::from(vec![Span::styled(
                            "can be used to restore your wallet.",
                            Style::default().fg(Color::Gray),
                        )]));
                        details.push(Line::from(""));
                        details.push(Line::from(vec![Span::styled(
                            "The backup is encrypted with your",
                            Style::default().fg(Color::Yellow),
                        )]));
                        details.push(Line::from(vec![Span::styled(
                            "passphrase. Keep it safe!",
                            Style::default().fg(Color::Yellow),
                        )]));
                        details.push(Line::from(""));
                        details.push(Line::from(vec![Span::styled(
                            "[Enter] Show backup string",
                            Style::default().fg(Color::DarkGray),
                        )]));
                    }
                }
            }
            SettingsSection::Network => {
                let (name, display_name, url) = NETWORKS[network_index];
                let is_current = name == current_network;
                let is_devnet = name == "devnet";

                details.push(Line::from(vec![
                    Span::styled("Network: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(display_name, Style::default().fg(Color::White)),
                ]));
                details.push(Line::from(""));
                details.push(Line::from(vec![
                    Span::styled("RPC URL: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(url, Style::default().fg(Color::Yellow)),
                ]));
                details.push(Line::from(""));

                if is_devnet {
                    details.push(Line::from(vec![Span::styled(
                        "Dev Features:",
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD),
                    )]));
                    details.push(Line::from(vec![Span::styled(
                        "  - Manual/auto block mining",
                        Style::default().fg(Color::Gray),
                    )]));
                    details.push(Line::from(vec![Span::styled(
                        "  - State checkpoints & reset",
                        Style::default().fg(Color::Gray),
                    )]));
                    details.push(Line::from(vec![Span::styled(
                        "  - Built-in faucet",
                        Style::default().fg(Color::Gray),
                    )]));
                } else if name == "mainnet" {
                    details.push(Line::from(vec![Span::styled(
                        "WARNING: Real funds!",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )]));
                    details.push(Line::from(vec![Span::styled(
                        "Transactions cannot be reversed.",
                        Style::default().fg(Color::Red),
                    )]));
                } else {
                    details.push(Line::from(vec![Span::styled(
                        "Test network for development",
                        Style::default().fg(Color::Gray),
                    )]));
                    details.push(Line::from(vec![Span::styled(
                        "Tokens have no real value",
                        Style::default().fg(Color::Gray),
                    )]));
                }

                details.push(Line::from(""));
                let action_hint = if is_current {
                    "[Currently active]"
                } else {
                    "[Enter] Switch to this network"
                };
                details.push(Line::from(vec![Span::styled(
                    action_hint,
                    Style::default().fg(Color::DarkGray),
                )]));
            }
        }

        // Show error/success messages
        if let Some(err) = error_message {
            details.push(Line::from(""));
            details.push(Line::from(vec![Span::styled(
                format!("Error: {}", err),
                Style::default().fg(Color::Red),
            )]));
        }
        if let Some(msg) = success_message {
            details.push(Line::from(""));
            details.push(Line::from(vec![Span::styled(
                msg,
                Style::default().fg(Color::Green),
            )]));
        }

        let details_widget = Paragraph::new(details).block(
            Block::default()
                .title("Details")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

        f.render_widget(details_widget, chunks[1]);
    }

    fn draw_backup_overlay(f: &mut Frame, area: Rect, backup_string: Option<&str>) {
        let backup = backup_string.unwrap_or("No backup available");

        let block = Block::default()
            .title("Wallet Backup")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let inner = block.inner(area);
        f.render_widget(block, area);

        let chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(inner);

        // Warning
        let warning = Paragraph::new(vec![
            Line::from(vec![Span::styled(
                "Keep this backup string safe and secret!",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(vec![Span::styled(
                "Anyone with this string and your passphrase can access your funds.",
                Style::default().fg(Color::Yellow),
            )]),
        ]);
        f.render_widget(warning, chunks[0]);

        // Backup string
        let backup_widget = Paragraph::new(backup)
            .style(Style::default().fg(Color::Green))
            .block(
                Block::default()
                    .title("Backup String (copy this)")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green)),
            )
            .wrap(Wrap { trim: false });
        f.render_widget(backup_widget, chunks[1]);

        // Hint
        let hint = Paragraph::new(vec![Line::from(vec![Span::styled(
            "[Esc] Close    [Enter] Close",
            Style::default().fg(Color::DarkGray),
        )])]);
        f.render_widget(hint, chunks[2]);
    }

    fn draw_passphrase_overlay(
        f: &mut Frame,
        area: Rect,
        passphrase_input: &str,
        error_message: Option<&str>,
    ) {
        let block = Block::default()
            .title("Enter Passphrase")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        let inner = block.inner(area);
        f.render_widget(block, area);

        let chunks = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(0),
        ])
        .split(inner);

        // Instructions
        let instructions = Paragraph::new(vec![Line::from(vec![Span::styled(
            "Enter your wallet passphrase to export the backup:",
            Style::default().fg(Color::Gray),
        )])]);
        f.render_widget(instructions, chunks[0]);

        // Passphrase input (show masked)
        let masked: String = "*".repeat(passphrase_input.len());
        let input_widget = Paragraph::new(masked)
            .style(Style::default().fg(Color::White))
            .block(
                Block::default()
                    .title("Passphrase")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            );
        f.render_widget(input_widget, chunks[1]);

        // Error message or hint
        let hint_text = if let Some(err) = error_message {
            Line::from(vec![Span::styled(
                format!("Error: {}", err),
                Style::default().fg(Color::Red),
            )])
        } else {
            Line::from(vec![Span::styled(
                "[Enter] Confirm    [Esc] Cancel",
                Style::default().fg(Color::DarkGray),
            )])
        };
        let hint = Paragraph::new(vec![hint_text]);
        f.render_widget(hint, chunks[2]);
    }
}

impl Component for SettingsComponent {
    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        // Handle backup overlay mode
        if self.mode == SettingsMode::ShowingBackup {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.mode = SettingsMode::Menu;
                    self.backup_string = None;
                }
                _ => {}
            }
            return Ok(());
        }

        // Handle passphrase input mode
        if self.mode == SettingsMode::EnteringPassphrase {
            match key.code {
                KeyCode::Esc => {
                    self.mode = SettingsMode::Menu;
                    self.passphrase_input.clear();
                    self.error_message = None;
                }
                KeyCode::Enter => {
                    if !self.passphrase_input.is_empty() {
                        // Send action to export with the entered passphrase
                        self.action_tx
                            .send(Action::ExportWalletBackupWithPassphrase(
                                self.passphrase_input.clone(),
                            ))?;
                    }
                }
                KeyCode::Backspace => {
                    self.passphrase_input.pop();
                }
                KeyCode::Char(c) => {
                    self.passphrase_input.push(c);
                }
                _ => {}
            }
            return Ok(());
        }

        // Normal menu mode
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.next_item();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.previous_item();
            }
            KeyCode::Enter => {
                self.select_current()?;
            }
            _ => {}
        }
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame, area: Rect) {
        Self::draw_static(
            f,
            area,
            &self.current_network,
            self.mode,
            self.section,
            self.wallet_index,
            self.network_index,
            self.backup_string.as_deref(),
            self.error_message.as_deref(),
            self.success_message.as_deref(),
            &self.passphrase_input,
        );
    }
}
