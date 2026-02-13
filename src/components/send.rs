//! Send component for sending CKB to stealth addresses or CKB addresses.

use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    action::{Action, PassphrasePurpose},
    domain::account::Account,
    tui::Frame,
};

use super::Component;

/// Input field focus state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendField {
    Recipient,
    Amount,
    Confirm,
}

/// Type of recipient address
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Stealth address (132 hex chars)
    Stealth,
    /// CKB address (ckb1.../ckt1...)
    Ckb,
    /// Unknown/invalid
    Unknown,
}

/// Component for sending CKB to stealth addresses or CKB addresses.
pub struct SendComponent {
    action_tx: UnboundedSender<Action>,
    pub account: Option<Account>,
    pub recipient: String,
    pub amount: String,
    pub focused_field: SendField,
    pub is_editing: bool,
    pub error_message: Option<String>,
    pub success_message: Option<String>,
}

impl SendComponent {
    pub fn new(action_tx: UnboundedSender<Action>) -> Self {
        Self {
            action_tx,
            account: None,
            recipient: String::new(),
            amount: String::new(),
            focused_field: SendField::Recipient,
            is_editing: false,
            error_message: None,
            success_message: None,
        }
    }

    /// Set the current account to send from.
    pub fn set_account(&mut self, account: Option<Account>) {
        self.account = account;
    }

    /// Clear all input fields.
    pub fn clear(&mut self) {
        self.recipient.clear();
        self.amount.clear();
        self.focused_field = SendField::Recipient;
        self.is_editing = false;
        self.error_message = None;
        self.success_message = None;
    }

    /// Request passphrase popup for signing transaction
    pub fn start_passphrase_input(&mut self) {
        self.error_message = None;
        let _ = self.action_tx.send(Action::ShowPassphrasePopup(
            PassphrasePurpose::SendTransaction,
        ));
    }

    /// Detect the type of address from recipient string.
    pub fn detect_address_type(&self) -> AddressType {
        let recipient = self.recipient.trim();
        if recipient.is_empty() {
            return AddressType::Unknown;
        }

        // Check for CKB address (starts with ckb1 or ckt1)
        if recipient.starts_with("ckb1") || recipient.starts_with("ckt1") {
            return AddressType::Ckb;
        }

        // Check for stealth address (132 hex chars, optionally with 0x prefix)
        let hex_str = recipient.trim_start_matches("0x");
        if hex_str.len() == 132 && hex::decode(hex_str).is_ok() {
            return AddressType::Stealth;
        }

        AddressType::Unknown
    }

    /// Parse the amount string to shannons (u64).
    pub fn parse_amount(&self) -> Option<u64> {
        let s = self.amount.trim();
        if s.is_empty() {
            return None;
        }

        // Try parsing as a decimal CKB amount
        let mut parts = s.split('.');
        let int = parts.next()?;
        let frac = parts.next().unwrap_or("");

        if parts.next().is_some() || frac.len() > 8 {
            return None;
        }

        let frac_padded = format!("{:0<8}", frac);
        format!("{}{}", int, frac_padded).parse().ok()
    }

    /// Validate inputs and return error message if invalid.
    pub fn validate(&self) -> Option<String> {
        if self.account.is_none() {
            return Some("No account selected".to_string());
        }

        if self.recipient.trim().is_empty() {
            return Some("Recipient address is required".to_string());
        }

        // Validate address based on type
        match self.detect_address_type() {
            AddressType::Unknown => Some(
                "Invalid address format. Use stealth (132 hex) or CKB (ckb1.../ckt1...)"
                    .to_string(),
            ),
            AddressType::Stealth => {
                // Already validated in detect_address_type
                None
            }
            AddressType::Ckb => {
                // Try to parse as CKB address
                use ckb_sdk::Address;
                use std::str::FromStr;
                if Address::from_str(self.recipient.trim()).is_err() {
                    return Some("Invalid CKB address format".to_string());
                }
                None
            }
        }?;

        match self.parse_amount() {
            None => Some("Invalid amount format".to_string()),
            Some(0) => Some("Amount must be greater than 0".to_string()),
            Some(amount) => {
                if let Some(ref acc) = self.account {
                    if amount > acc.ckb_balance {
                        Some(format!(
                            "Insufficient balance: {} > {}",
                            format_ckb(amount),
                            format_ckb(acc.ckb_balance)
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        }
    }

    fn next_field(&mut self) {
        self.focused_field = match self.focused_field {
            SendField::Recipient => SendField::Amount,
            SendField::Amount => SendField::Confirm,
            SendField::Confirm => SendField::Recipient,
        };
    }

    fn prev_field(&mut self) {
        self.focused_field = match self.focused_field {
            SendField::Recipient => SendField::Confirm,
            SendField::Amount => SendField::Recipient,
            SendField::Confirm => SendField::Amount,
        };
    }

    fn handle_char(&mut self, c: char) {
        match self.focused_field {
            SendField::Recipient => {
                self.recipient.push(c);
            }
            SendField::Amount => {
                // Only allow digits and decimal point
                if c.is_ascii_digit() || (c == '.' && !self.amount.contains('.')) {
                    self.amount.push(c);
                }
            }
            SendField::Confirm => {}
        }
    }

    fn handle_backspace(&mut self) {
        match self.focused_field {
            SendField::Recipient => {
                self.recipient.pop();
            }
            SendField::Amount => {
                self.amount.pop();
            }
            SendField::Confirm => {}
        }
    }

    pub fn paste(&mut self, text: &str) {
        if !self.is_editing {
            return;
        }
        match self.focused_field {
            SendField::Recipient => {
                self.recipient.push_str(text);
            }
            SendField::Amount => {
                for c in text.chars() {
                    if c.is_ascii_digit() || (c == '.' && !self.amount.contains('.')) {
                        self.amount.push(c);
                    }
                }
            }
            SendField::Confirm => {}
        }
    }

    /// Static draw method for use in the main app draw loop.
    #[allow(clippy::too_many_arguments)]
    pub fn draw_static(
        f: &mut Frame,
        area: Rect,
        account: Option<&Account>,
        recipient: &str,
        amount: &str,
        address_type: AddressType,
        focused_field: SendField,
        is_editing: bool,
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
        let account_info = if let Some(acc) = account {
            vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("From: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&acc.name, Style::default().fg(Color::White)),
                    Span::raw("  |  "),
                    Span::styled("Balance: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format_ckb(acc.ckb_balance),
                        Style::default().fg(Color::Green),
                    ),
                ]),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "No account selected. Select an account first.",
                    Style::default().fg(Color::Red),
                )]),
            ]
        };

        let account_widget = Paragraph::new(account_info).block(
            Block::default()
                .title("Send From")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(account_widget, chunks[0]);

        // Recipient input
        let recipient_style = if focused_field == SendField::Recipient {
            if is_editing {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Cyan)
            }
        } else {
            Style::default().fg(Color::White)
        };

        let recipient_text = if recipient.is_empty() && focused_field != SendField::Recipient {
            "Enter address (stealth or CKB)"
        } else if recipient.is_empty() {
            "│"
        } else {
            recipient
        };

        let mut recipient_display = recipient_text.to_string();
        if is_editing && focused_field == SendField::Recipient {
            recipient_display.push('│');
        }

        // Determine title based on address type
        let title_prefix = if focused_field == SendField::Recipient {
            "> "
        } else {
            "  "
        };

        let type_indicator = match address_type {
            AddressType::Stealth => " [Stealth]",
            AddressType::Ckb => " [CKB Address]",
            AddressType::Unknown => {
                if recipient.is_empty() {
                    " [Stealth or CKB Address]"
                } else {
                    " [Invalid]"
                }
            }
        };

        let recipient_widget = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled(recipient_display, recipient_style)]),
        ])
        .block(
            Block::default()
                .title(format!("{}Recipient{}", title_prefix, type_indicator))
                .borders(Borders::ALL)
                .border_style(if focused_field == SendField::Recipient {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        );
        f.render_widget(recipient_widget, chunks[1]);

        // Amount input
        let amount_style = if focused_field == SendField::Amount {
            if is_editing {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Cyan)
            }
        } else {
            Style::default().fg(Color::White)
        };

        let amount_text = if amount.is_empty() && focused_field != SendField::Amount {
            "Enter amount in CKB (e.g., 100.5)"
        } else if amount.is_empty() {
            "│"
        } else {
            amount
        };

        let mut amount_display = amount_text.to_string();
        if is_editing && focused_field == SendField::Amount {
            amount_display.push('│');
        }

        let amount_widget = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(amount_display, amount_style),
                Span::raw(" CKB"),
            ]),
        ])
        .block(
            Block::default()
                .title(if focused_field == SendField::Amount {
                    "> Amount"
                } else {
                    "  Amount"
                })
                .borders(Borders::ALL)
                .border_style(if focused_field == SendField::Amount {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        );
        f.render_widget(amount_widget, chunks[2]);

        // Confirm button
        let confirm_style = if focused_field == SendField::Confirm {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Green)
        };

        let confirm_widget = Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "  [ Send Transaction ]  ",
                confirm_style,
            )]),
        ])
        .block(
            Block::default()
                .title(if focused_field == SendField::Confirm {
                    "> Confirm"
                } else {
                    "  Confirm"
                })
                .borders(Borders::ALL)
                .border_style(if focused_field == SendField::Confirm {
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
            if is_editing {
                "ESC: Stop editing | Enter: Confirm and next field"
            } else {
                "Up/Down: Navigate | Enter: Edit/Confirm"
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
}

impl Component for SendComponent {
    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        self.error_message = None;

        let on_input_field =
            self.focused_field == SendField::Recipient || self.focused_field == SendField::Amount;

        if self.is_editing && on_input_field {
            // Editing mode - handle character input
            match key.code {
                KeyCode::Esc => {
                    self.is_editing = false;
                }
                KeyCode::Enter => {
                    // Confirm current field and move to next
                    self.is_editing = false;
                    self.next_field();
                }
                KeyCode::Char(c) => {
                    self.handle_char(c);
                }
                KeyCode::Backspace => {
                    self.handle_backspace();
                }
                _ => {}
            }
        } else {
            // Navigation mode
            match key.code {
                KeyCode::Down => {
                    self.next_field();
                }
                KeyCode::Up => {
                    self.prev_field();
                }
                KeyCode::Enter => {
                    if self.focused_field == SendField::Confirm {
                        if let Some(err) = self.validate() {
                            self.error_message = Some(err);
                        } else {
                            // Start passphrase input instead of directly sending
                            self.start_passphrase_input();
                        }
                    } else if on_input_field {
                        // Enter on input field starts editing mode
                        self.is_editing = true;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame, area: Rect) {
        Self::draw_static(
            f,
            area,
            self.account.as_ref(),
            &self.recipient,
            &self.amount,
            self.detect_address_type(),
            self.focused_field,
            self.is_editing,
            self.error_message.as_deref(),
            self.success_message.as_deref(),
        );
    }
}

fn format_ckb(shannon: u64) -> String {
    let ckb = shannon / 100_000_000;
    let frac = shannon % 100_000_000;
    format!("{}.{:08} CKB", ckb, frac)
}
