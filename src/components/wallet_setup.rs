//! Wallet setup component for first-time initialization and restore.

use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{action::Action, tui::Frame};

use super::Component;

/// The setup mode - what action the user wants to take
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupMode {
    /// Initial menu: Create, Restore from Mnemonic, or Restore from Backup
    Menu,
    /// Creating a new wallet - enter passphrase
    CreatePassphrase,
    /// Creating a new wallet - confirm passphrase
    CreateConfirmPassphrase,
    /// Creating a new wallet - show mnemonic
    ShowMnemonic,
    /// Restoring from mnemonic - enter passphrase first
    RestoreMnemonicPassphrase,
    /// Restoring from mnemonic - enter the 24 words
    RestoreMnemonicInput,
    /// Restoring from backup - enter the backup string first
    RestoreBackupInput,
    /// Restoring from backup - enter passphrase to decrypt
    RestoreBackupPassphrase,
}

/// Menu item selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    CreateNew,
    RestoreMnemonic,
    RestoreBackup,
}

impl MenuItem {
    fn next(self) -> Self {
        match self {
            MenuItem::CreateNew => MenuItem::RestoreMnemonic,
            MenuItem::RestoreMnemonic => MenuItem::RestoreBackup,
            MenuItem::RestoreBackup => MenuItem::CreateNew,
        }
    }

    fn prev(self) -> Self {
        match self {
            MenuItem::CreateNew => MenuItem::RestoreBackup,
            MenuItem::RestoreMnemonic => MenuItem::CreateNew,
            MenuItem::RestoreBackup => MenuItem::RestoreMnemonic,
        }
    }
}

/// Component for wallet setup (create new or restore)
pub struct WalletSetupComponent {
    action_tx: UnboundedSender<Action>,
    pub mode: SetupMode,
    pub selected_menu: MenuItem,

    // Passphrase input
    pub passphrase: String,
    pub passphrase_confirm: String,
    pub show_passphrase: bool,

    // Mnemonic (generated or being entered)
    pub mnemonic_words: Vec<String>,
    pub mnemonic_input: String, // For restore - space-separated words

    // Backup string for restore
    pub backup_input: String,

    // Error/success messages
    pub error_message: Option<String>,
    pub success_message: Option<String>,
}

impl WalletSetupComponent {
    pub fn new(action_tx: UnboundedSender<Action>) -> Self {
        Self {
            action_tx,
            mode: SetupMode::Menu,
            selected_menu: MenuItem::CreateNew,
            passphrase: String::new(),
            passphrase_confirm: String::new(),
            show_passphrase: false,
            mnemonic_words: Vec::new(),
            mnemonic_input: String::new(),
            backup_input: String::new(),
            error_message: None,
            success_message: None,
        }
    }

    /// Reset to initial state
    pub fn reset(&mut self) {
        self.mode = SetupMode::Menu;
        self.selected_menu = MenuItem::CreateNew;
        self.passphrase.clear();
        self.passphrase_confirm.clear();
        self.show_passphrase = false;
        self.mnemonic_words.clear();
        self.mnemonic_input.clear();
        self.backup_input.clear();
        self.error_message = None;
        self.success_message = None;
    }

    /// Set the generated mnemonic words
    pub fn set_mnemonic(&mut self, mnemonic: &str) {
        self.mnemonic_words = mnemonic.split_whitespace().map(String::from).collect();
    }

    /// Get the mnemonic as a single string
    pub fn get_mnemonic(&self) -> String {
        if !self.mnemonic_input.is_empty() {
            // For restore, use the input
            self.mnemonic_input.trim().to_string()
        } else {
            // For create, use the generated words
            self.mnemonic_words.join(" ")
        }
    }

    /// Get the passphrase
    pub fn get_passphrase(&self) -> &str {
        &self.passphrase
    }

    /// Get the backup input
    pub fn get_backup_input(&self) -> &str {
        &self.backup_input
    }

    /// Validate passphrase
    fn validate_passphrase(&self) -> Option<String> {
        if self.passphrase.is_empty() {
            return Some("Passphrase cannot be empty".to_string());
        }
        if self.passphrase.len() < 8 {
            return Some("Passphrase must be at least 8 characters".to_string());
        }
        None
    }

    /// Validate passphrase confirmation
    fn validate_confirm(&self) -> Option<String> {
        if self.passphrase != self.passphrase_confirm {
            return Some("Passphrases do not match".to_string());
        }
        None
    }

    /// Validate mnemonic input (24 words)
    fn validate_mnemonic_input(&self) -> Option<String> {
        let words: Vec<&str> = self.mnemonic_input.split_whitespace().collect();
        if words.len() != 24 {
            return Some(format!("Mnemonic must be 24 words (got {})", words.len()));
        }
        None
    }

    /// Validate backup input
    fn validate_backup_input(&self) -> Option<String> {
        if !self.backup_input.starts_with("obscell:1:") {
            return Some("Invalid backup format (should start with 'obscell:1:')".to_string());
        }
        None
    }

    /// Handle character input for the current field
    fn handle_char(&mut self, c: char) {
        match self.mode {
            SetupMode::CreatePassphrase
            | SetupMode::RestoreMnemonicPassphrase
            | SetupMode::RestoreBackupPassphrase => {
                self.passphrase.push(c);
            }
            SetupMode::CreateConfirmPassphrase => {
                self.passphrase_confirm.push(c);
            }
            SetupMode::RestoreMnemonicInput => {
                self.mnemonic_input.push(c);
            }
            SetupMode::RestoreBackupInput => {
                self.backup_input.push(c);
            }
            _ => {}
        }
        self.error_message = None;
    }

    /// Handle backspace for the current field
    fn handle_backspace(&mut self) {
        match self.mode {
            SetupMode::CreatePassphrase
            | SetupMode::RestoreMnemonicPassphrase
            | SetupMode::RestoreBackupPassphrase => {
                self.passphrase.pop();
            }
            SetupMode::CreateConfirmPassphrase => {
                self.passphrase_confirm.pop();
            }
            SetupMode::RestoreMnemonicInput => {
                self.mnemonic_input.pop();
            }
            SetupMode::RestoreBackupInput => {
                self.backup_input.pop();
            }
            _ => {}
        }
        self.error_message = None;
    }

    /// Handle paste (called externally with pasted text)
    pub fn paste(&mut self, text: &str) {
        match self.mode {
            SetupMode::CreatePassphrase
            | SetupMode::RestoreMnemonicPassphrase
            | SetupMode::RestoreBackupPassphrase => {
                self.passphrase.push_str(text);
            }
            SetupMode::CreateConfirmPassphrase => {
                self.passphrase_confirm.push_str(text);
            }
            SetupMode::RestoreMnemonicInput => {
                self.mnemonic_input.push_str(text);
            }
            SetupMode::RestoreBackupInput => {
                self.backup_input.push_str(text);
            }
            _ => {}
        }
        self.error_message = None;
    }

    /// Handle Enter key based on current mode
    fn handle_enter(&mut self) {
        self.error_message = None;

        match self.mode {
            SetupMode::Menu => match self.selected_menu {
                MenuItem::CreateNew => {
                    self.mode = SetupMode::CreatePassphrase;
                }
                MenuItem::RestoreMnemonic => {
                    self.mode = SetupMode::RestoreMnemonicPassphrase;
                }
                MenuItem::RestoreBackup => {
                    self.mode = SetupMode::RestoreBackupInput;
                }
            },
            SetupMode::CreatePassphrase => {
                if let Some(err) = self.validate_passphrase() {
                    self.error_message = Some(err);
                } else {
                    self.mode = SetupMode::CreateConfirmPassphrase;
                }
            }
            SetupMode::CreateConfirmPassphrase => {
                if let Some(err) = self.validate_confirm() {
                    self.error_message = Some(err);
                } else {
                    // Generate mnemonic and move to show screen
                    let _ = self.action_tx.send(Action::GenerateMnemonic);
                }
            }
            SetupMode::ShowMnemonic => {
                // User confirmed they've saved the mnemonic
                let _ = self.action_tx.send(Action::CreateWallet);
            }
            SetupMode::RestoreMnemonicPassphrase => {
                if let Some(err) = self.validate_passphrase() {
                    self.error_message = Some(err);
                } else {
                    self.mode = SetupMode::RestoreMnemonicInput;
                }
            }
            SetupMode::RestoreMnemonicInput => {
                if let Some(err) = self.validate_mnemonic_input() {
                    self.error_message = Some(err);
                } else {
                    let _ = self.action_tx.send(Action::RestoreFromMnemonic);
                }
            }
            SetupMode::RestoreBackupInput => {
                if let Some(err) = self.validate_backup_input() {
                    self.error_message = Some(err);
                } else {
                    self.mode = SetupMode::RestoreBackupPassphrase;
                }
            }
            SetupMode::RestoreBackupPassphrase => {
                if let Some(err) = self.validate_passphrase() {
                    self.error_message = Some(err);
                } else {
                    let _ = self.action_tx.send(Action::RestoreFromBackup);
                }
            }
        }
    }

    /// Handle Escape key - go back or cancel
    fn handle_escape(&mut self) {
        match self.mode {
            SetupMode::Menu => {
                // Can't escape from menu
            }
            SetupMode::CreatePassphrase
            | SetupMode::RestoreMnemonicPassphrase
            | SetupMode::RestoreBackupInput => {
                self.reset();
            }
            SetupMode::CreateConfirmPassphrase => {
                self.passphrase_confirm.clear();
                self.mode = SetupMode::CreatePassphrase;
            }
            SetupMode::ShowMnemonic => {
                // Can't go back from mnemonic display - must continue or restart
                self.reset();
            }
            SetupMode::RestoreMnemonicInput => {
                self.mnemonic_input.clear();
                self.mode = SetupMode::RestoreMnemonicPassphrase;
            }
            SetupMode::RestoreBackupPassphrase => {
                self.passphrase.clear();
                self.mode = SetupMode::RestoreBackupInput;
            }
        }
        self.error_message = None;
    }

    /// Draw static version for data extraction pattern
    #[allow(clippy::too_many_arguments)]
    pub fn draw_static(
        f: &mut Frame,
        area: Rect,
        mode: SetupMode,
        selected_menu: MenuItem,
        passphrase: &str,
        passphrase_confirm: &str,
        show_passphrase: bool,
        mnemonic_words: &[String],
        mnemonic_input: &str,
        backup_input: &str,
        error_message: Option<&str>,
        _success_message: Option<&str>,
    ) {
        // Clear the area
        f.render_widget(Clear, area);

        // Main container
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Obscell Wallet Setup ");

        let inner = block.inner(area);
        f.render_widget(block, area);

        // Layout: title, content, status
        let chunks = Layout::vertical([
            Constraint::Length(3), // Title
            Constraint::Min(10),   // Content
            Constraint::Length(3), // Status/error
            Constraint::Length(2), // Help
        ])
        .split(inner);

        // Title
        let title = match mode {
            SetupMode::Menu => "Welcome to Obscell Wallet",
            SetupMode::CreatePassphrase => "Create New Wallet - Set Passphrase",
            SetupMode::CreateConfirmPassphrase => "Create New Wallet - Confirm Passphrase",
            SetupMode::ShowMnemonic => "Create New Wallet - Save Your Mnemonic",
            SetupMode::RestoreMnemonicPassphrase => "Restore from Mnemonic - Set Passphrase",
            SetupMode::RestoreMnemonicInput => "Restore from Mnemonic - Enter 24 Words",
            SetupMode::RestoreBackupInput => "Restore from Backup - Enter Backup String",
            SetupMode::RestoreBackupPassphrase => "Restore from Backup - Enter Passphrase",
        };
        let title_para = Paragraph::new(title)
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(title_para, chunks[0]);

        // Content based on mode
        match mode {
            SetupMode::Menu => {
                Self::draw_menu(f, chunks[1], selected_menu);
            }
            SetupMode::CreatePassphrase | SetupMode::RestoreMnemonicPassphrase => {
                Self::draw_passphrase_input(f, chunks[1], passphrase, show_passphrase, None);
            }
            SetupMode::RestoreBackupPassphrase => {
                Self::draw_passphrase_input(
                    f,
                    chunks[1],
                    passphrase,
                    show_passphrase,
                    Some("Enter passphrase to decrypt backup:"),
                );
            }
            SetupMode::CreateConfirmPassphrase => {
                Self::draw_passphrase_input(
                    f,
                    chunks[1],
                    passphrase_confirm,
                    show_passphrase,
                    Some("Re-enter your passphrase to confirm:"),
                );
            }
            SetupMode::ShowMnemonic => {
                Self::draw_mnemonic_display(f, chunks[1], mnemonic_words);
            }
            SetupMode::RestoreMnemonicInput => {
                Self::draw_mnemonic_input(f, chunks[1], mnemonic_input);
            }
            SetupMode::RestoreBackupInput => {
                Self::draw_backup_input(f, chunks[1], backup_input);
            }
        }

        // Error/status message
        if let Some(err) = error_message {
            let error_para = Paragraph::new(err)
                .style(Style::default().fg(Color::Red))
                .alignment(ratatui::layout::Alignment::Center);
            f.render_widget(error_para, chunks[2]);
        }

        // Help text
        let help = match mode {
            SetupMode::Menu => "↑/↓: Navigate  Enter: Select  q: Quit",
            SetupMode::ShowMnemonic => "IMPORTANT: Write down these words! Press Enter when done.",
            _ => "Enter: Continue  Esc: Back  Tab: Toggle show/hide  Ctrl+V: Paste",
        };
        let help_para = Paragraph::new(help)
            .style(Style::default().fg(Color::DarkGray))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(help_para, chunks[3]);
    }

    fn draw_menu(f: &mut Frame, area: Rect, selected: MenuItem) {
        let items = [
            (
                MenuItem::CreateNew,
                "Create New Wallet",
                "Generate a new 24-word mnemonic",
            ),
            (
                MenuItem::RestoreMnemonic,
                "Restore from Mnemonic",
                "Enter your 24 words to recover",
            ),
            (
                MenuItem::RestoreBackup,
                "Restore from Backup",
                "Import an encrypted backup string",
            ),
        ];

        let chunks = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Min(0),
        ])
        .split(area);

        for (i, (item, label, desc)) in items.iter().enumerate() {
            let is_selected = *item == selected;
            let style = if is_selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let prefix = if is_selected { "▶ " } else { "  " };
            let text = vec![
                Line::from(Span::styled(format!("{}{}", prefix, label), style)),
                Line::from(Span::styled(
                    format!("    {}", desc),
                    Style::default().fg(Color::DarkGray),
                )),
            ];
            let para = Paragraph::new(text);
            f.render_widget(para, chunks[i + 1]);
        }
    }

    fn draw_passphrase_input(
        f: &mut Frame,
        area: Rect,
        passphrase: &str,
        show: bool,
        custom_instruction: Option<&str>,
    ) {
        let chunks = Layout::vertical([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(0),
        ])
        .split(area);

        // Instructions
        let instructions =
            custom_instruction.unwrap_or("Enter a strong passphrase (min 8 characters):");
        let instr_para = Paragraph::new(instructions).style(Style::default().fg(Color::White));
        f.render_widget(instr_para, chunks[0]);

        // Password field
        let display = if show {
            format!("{}│", passphrase)
        } else {
            format!("{}│", "*".repeat(passphrase.len()))
        };

        let input_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow))
            .title(if show {
                " Passphrase (visible) "
            } else {
                " Passphrase "
            });

        let input_para = Paragraph::new(display)
            .style(Style::default().fg(Color::White))
            .block(input_block);
        f.render_widget(input_para, chunks[1]);

        // Show/hide hint
        let hint = format!(
            "Press Tab to {} passphrase",
            if show { "hide" } else { "show" }
        );
        let hint_para = Paragraph::new(hint).style(Style::default().fg(Color::DarkGray));
        f.render_widget(hint_para, chunks[2]);
    }

    fn draw_mnemonic_display(f: &mut Frame, area: Rect, words: &[String]) {
        let chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(2),
        ])
        .split(area);

        // Warning
        let warning =
            Paragraph::new("⚠️  Write down these 24 words in order. Store them safely offline.")
                .style(Style::default().fg(Color::Yellow))
                .wrap(Wrap { trim: true });
        f.render_widget(warning, chunks[0]);

        // Words in 4 columns
        if words.len() == 24 {
            let col_chunks = Layout::horizontal([
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
                Constraint::Percentage(25),
            ])
            .split(chunks[1]);

            for col in 0..4 {
                let mut lines = Vec::new();
                for row in 0..6 {
                    let idx = row * 4 + col;
                    if idx < words.len() {
                        lines.push(Line::from(format!("{:2}. {}", idx + 1, words[idx])));
                    }
                }
                let para = Paragraph::new(lines).style(Style::default().fg(Color::Green));
                f.render_widget(para, col_chunks[col]);
            }
        }

        // Confirmation hint
        let confirm = Paragraph::new("Press Enter after you have saved these words")
            .style(Style::default().fg(Color::Cyan))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(confirm, chunks[2]);
    }

    fn draw_mnemonic_input(f: &mut Frame, area: Rect, input: &str) {
        let chunks = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(4),
            Constraint::Length(2),
        ])
        .split(area);

        // Instructions
        let instructions = Paragraph::new("Enter your 24-word mnemonic (space-separated):")
            .style(Style::default().fg(Color::White));
        f.render_widget(instructions, chunks[0]);

        // Input area
        let word_count = input.split_whitespace().count();
        let title = format!(" Mnemonic ({}/24 words) ", word_count);
        let input_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if word_count == 24 {
                Color::Green
            } else {
                Color::Yellow
            }))
            .title(title);

        let display = format!("{}│", input);
        let input_para = Paragraph::new(display)
            .style(Style::default().fg(Color::White))
            .block(input_block)
            .wrap(Wrap { trim: false });
        f.render_widget(input_para, chunks[1]);

        // Hint
        let hint = Paragraph::new("Paste with Ctrl+V or type words separated by spaces")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(hint, chunks[2]);
    }

    fn draw_backup_input(f: &mut Frame, area: Rect, input: &str) {
        let chunks = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(4),
            Constraint::Length(2),
        ])
        .split(area);

        // Instructions
        let instructions = Paragraph::new("Enter your backup string (starts with 'obscell:1:'):")
            .style(Style::default().fg(Color::White));
        f.render_widget(instructions, chunks[0]);

        // Input area
        let is_valid_prefix = input.starts_with("obscell:1:");
        let input_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if is_valid_prefix {
                Color::Green
            } else {
                Color::Yellow
            }))
            .title(" Backup String ");

        let display = format!("{}│", input);
        let input_para = Paragraph::new(display)
            .style(Style::default().fg(Color::White))
            .block(input_block)
            .wrap(Wrap { trim: false });
        f.render_widget(input_para, chunks[1]);

        // Hint
        let hint = Paragraph::new("Paste with Ctrl+V").style(Style::default().fg(Color::DarkGray));
        f.render_widget(hint, chunks[2]);
    }
}

impl Component for WalletSetupComponent {
    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        // Note: Ctrl+V paste is handled by the App via paste events

        match key.code {
            KeyCode::Enter => self.handle_enter(),
            KeyCode::Esc => self.handle_escape(),
            KeyCode::Tab => {
                // Toggle show/hide passphrase
                self.show_passphrase = !self.show_passphrase;
            }
            KeyCode::Up => {
                if self.mode == SetupMode::Menu {
                    self.selected_menu = self.selected_menu.prev();
                }
            }
            KeyCode::Down => {
                if self.mode == SetupMode::Menu {
                    self.selected_menu = self.selected_menu.next();
                }
            }
            KeyCode::Char(c) => {
                if self.mode == SetupMode::Menu {
                    // Menu-specific hotkeys
                    match c {
                        'k' => self.selected_menu = self.selected_menu.prev(),
                        'j' => self.selected_menu = self.selected_menu.next(),
                        'q' => {
                            let _ = self.action_tx.send(Action::Quit);
                        }
                        _ => {}
                    }
                } else {
                    // Input modes: all characters are text input
                    self.handle_char(c);
                }
            }
            KeyCode::Backspace => self.handle_backspace(),
            _ => {}
        }

        Ok(())
    }

    fn draw(&mut self, f: &mut Frame, area: Rect) {
        Self::draw_static(
            f,
            area,
            self.mode,
            self.selected_menu,
            &self.passphrase,
            &self.passphrase_confirm,
            self.show_passphrase,
            &self.mnemonic_words,
            &self.mnemonic_input,
            &self.backup_input,
            self.error_message.as_deref(),
            self.success_message.as_deref(),
        );
    }
}
