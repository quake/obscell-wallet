//! Dev component for developer mode controls.

use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{action::Action, domain::account::Account, tui::Frame};

use super::Component;

/// Component for developer mode controls.
pub struct DevComponent {
    action_tx: UnboundedSender<Action>,
    pub account: Option<Account>,
    pub checkpoint: Option<u64>,
    pub auto_mining: bool,
    pub mining_interval: u64,
    pub miner_balance: Option<u64>,
    pub faucet_amount: String,
    pub is_editing: bool,
    pub error_message: Option<String>,
    pub success_message: Option<String>,
}

impl DevComponent {
    pub fn new(action_tx: UnboundedSender<Action>) -> Self {
        Self {
            action_tx,
            account: None,
            checkpoint: None,
            auto_mining: false,
            mining_interval: 3,
            miner_balance: None,
            faucet_amount: "1000".to_string(),
            is_editing: false,
            error_message: None,
            success_message: None,
        }
    }

    /// Set the current account (recipient for faucet).
    pub fn set_account(&mut self, account: Option<Account>) {
        self.account = account;
    }

    /// Set the saved checkpoint block number.
    pub fn set_checkpoint(&mut self, checkpoint: Option<u64>) {
        self.checkpoint = checkpoint;
    }

    /// Set the miner balance.
    pub fn set_miner_balance(&mut self, balance: Option<u64>) {
        self.miner_balance = balance;
    }

    /// Toggle auto-mining on/off.
    pub fn toggle_auto_mining(&mut self) {
        self.auto_mining = !self.auto_mining;
    }

    /// Increase mining interval (max 10s).
    pub fn increase_interval(&mut self) {
        if self.mining_interval < 10 {
            self.mining_interval += 1;
        }
    }

    /// Decrease mining interval (min 1s).
    pub fn decrease_interval(&mut self) {
        if self.mining_interval > 1 {
            self.mining_interval -= 1;
        }
    }

    /// Parse faucet amount to u64 (in CKB shannons, 8 decimal places).
    pub fn parse_faucet_amount(&self) -> Option<u64> {
        let s = self.faucet_amount.trim();
        if s.is_empty() {
            return None;
        }

        let mut parts = s.split('.');
        let int = parts.next()?;
        let frac = parts.next().unwrap_or("");

        if parts.next().is_some() || frac.len() > 8 {
            return None;
        }

        let frac_padded = format!("{:0<8}", frac);
        format!("{}{}", int, frac_padded).parse().ok()
    }

    /// Clear error and success messages.
    pub fn clear_messages(&mut self) {
        self.error_message = None;
        self.success_message = None;
    }

    fn handle_char(&mut self, c: char) {
        if c.is_ascii_digit() || (c == '.' && !self.faucet_amount.contains('.')) {
            self.faucet_amount.push(c);
        }
    }

    fn handle_backspace(&mut self) {
        self.faucet_amount.pop();
    }

    pub fn paste(&mut self, text: &str) {
        for c in text.chars() {
            if c.is_ascii_digit() || (c == '.' && !self.faucet_amount.contains('.')) {
                self.faucet_amount.push(c);
            }
        }
    }

    /// Static draw method for use in the main app draw loop.
    #[allow(clippy::too_many_arguments)]
    pub fn draw_static(
        f: &mut Frame,
        area: Rect,
        account: Option<&Account>,
        checkpoint: Option<u64>,
        auto_mining: bool,
        mining_interval: u64,
        miner_balance: Option<u64>,
        faucet_amount: &str,
        is_editing: bool,
        error_message: Option<&str>,
        success_message: Option<&str>,
    ) {
        let chunks = Layout::vertical([
            Constraint::Length(5), // Checkpoint section
            Constraint::Length(5), // Auto-mining section
            Constraint::Length(7), // Faucet section
            Constraint::Min(0),    // Status section
        ])
        .split(area);

        // Checkpoint section
        Self::draw_checkpoint_section(f, chunks[0], checkpoint);

        // Auto-mining section
        Self::draw_automining_section(f, chunks[1], auto_mining, mining_interval);

        // Faucet section
        Self::draw_faucet_section(
            f,
            chunks[2],
            account,
            miner_balance,
            faucet_amount,
            is_editing,
        );

        // Status section
        Self::draw_status_section(f, chunks[3], error_message, success_message);
    }

    fn draw_checkpoint_section(f: &mut Frame, area: Rect, checkpoint: Option<u64>) {
        let checkpoint_text = match checkpoint {
            Some(block) => format!("Block #{}", block),
            None => "Not saved".to_string(),
        };

        let content = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("Saved Checkpoint: ", Style::default().fg(Color::DarkGray)),
                Span::styled(checkpoint_text, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "[p] Save checkpoint  [x] Reset to checkpoint",
                Style::default().fg(Color::DarkGray),
            )]),
        ];

        let widget = Paragraph::new(content).block(
            Block::default()
                .title("Checkpoint")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

        f.render_widget(widget, area);
    }

    fn draw_automining_section(f: &mut Frame, area: Rect, auto_mining: bool, mining_interval: u64) {
        let status_style = if auto_mining {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Red)
        };

        let status_text = if auto_mining { "ON" } else { "OFF" };

        let content = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("Auto-mining: ", Style::default().fg(Color::DarkGray)),
                Span::styled(status_text, status_style),
                Span::raw("    "),
                Span::styled("Interval: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{}s", mining_interval),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "[g] Generate block  [m] Toggle mining  [+/-] Adjust interval",
                Style::default().fg(Color::DarkGray),
            )]),
        ];

        let widget = Paragraph::new(content).block(
            Block::default()
                .title("Auto-Mining")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

        f.render_widget(widget, area);
    }

    fn draw_faucet_section(
        f: &mut Frame,
        area: Rect,
        account: Option<&Account>,
        miner_balance: Option<u64>,
        faucet_amount: &str,
        is_editing: bool,
    ) {
        let balance_text = match miner_balance {
            Some(balance) => format_ckb_amount(balance),
            None => "Unknown".to_string(),
        };

        let recipient_text = match account {
            Some(acc) => acc.name.clone(),
            None => "No account selected".to_string(),
        };

        let amount_style = if is_editing {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::White)
        };

        let mut amount_display = faucet_amount.to_string();
        if is_editing {
            amount_display.push('│');
        }

        let content = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("Miner Balance: ", Style::default().fg(Color::DarkGray)),
                Span::styled(balance_text, Style::default().fg(Color::Green)),
                Span::raw(" CKB"),
            ]),
            Line::from(vec![
                Span::styled("Recipient: ", Style::default().fg(Color::DarkGray)),
                Span::styled(recipient_text, Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Amount: ", Style::default().fg(Color::DarkGray)),
                Span::styled(amount_display, amount_style),
                Span::raw(" CKB"),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "[e] Edit amount  [f] Send faucet",
                Style::default().fg(Color::DarkGray),
            )]),
        ];

        let widget = Paragraph::new(content).block(
            Block::default()
                .title("Faucet")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

        f.render_widget(widget, area);
    }

    fn draw_status_section(
        f: &mut Frame,
        area: Rect,
        error_message: Option<&str>,
        success_message: Option<&str>,
    ) {
        let mut content = vec![Line::from("")];

        if let Some(err) = error_message {
            content.push(Line::from(vec![Span::styled(
                format!("Error: {}", err),
                Style::default().fg(Color::Red),
            )]));
        } else if let Some(success) = success_message {
            content.push(Line::from(vec![Span::styled(
                success,
                Style::default().fg(Color::Green),
            )]));
        } else {
            content.push(Line::from(vec![Span::styled(
                "Developer mode enabled - Use devnet controls",
                Style::default().fg(Color::DarkGray),
            )]));
        }

        content.push(Line::from(""));
        content.push(Line::from(vec![Span::styled(
            "Hotkeys: [g]enerate [m]ine [+/-]interval [r]eset [s]ave [f]aucet [e]dit",
            Style::default().fg(Color::DarkGray),
        )]));

        let widget = Paragraph::new(content).block(
            Block::default()
                .title("Status")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

        f.render_widget(widget, area);
    }
}

impl Component for DevComponent {
    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        // Clear previous messages on any input
        self.error_message = None;

        if self.is_editing {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.is_editing = false;
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
            match key.code {
                KeyCode::Char('g') => {
                    self.action_tx.send(Action::GenerateBlock)?;
                }
                KeyCode::Char('m') => {
                    self.toggle_auto_mining();
                    self.action_tx.send(Action::ToggleAutoMining)?;
                }
                KeyCode::Char('+') | KeyCode::Char('=') => {
                    self.increase_interval();
                    self.action_tx
                        .send(Action::SetMiningInterval(self.mining_interval))?;
                }
                KeyCode::Char('-') | KeyCode::Char('_') => {
                    self.decrease_interval();
                    self.action_tx
                        .send(Action::SetMiningInterval(self.mining_interval))?;
                }
                KeyCode::Char('x') => {
                    self.action_tx.send(Action::ResetToCheckpoint)?;
                }
                KeyCode::Char('p') => {
                    self.action_tx.send(Action::SaveCheckpoint)?;
                }
                KeyCode::Char('f') => {
                    if self.account.is_none() {
                        self.error_message = Some("No account selected".to_string());
                    } else if self.parse_faucet_amount().is_none() {
                        self.error_message = Some("Invalid faucet amount".to_string());
                    } else {
                        self.action_tx.send(Action::SendFaucet)?;
                    }
                }
                KeyCode::Char('e') => {
                    self.is_editing = true;
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
            self.checkpoint,
            self.auto_mining,
            self.mining_interval,
            self.miner_balance,
            &self.faucet_amount,
            self.is_editing,
            self.error_message.as_deref(),
            self.success_message.as_deref(),
        );
    }
}

/// Format CKB amount for display (8 decimal places, in shannons).
fn format_ckb_amount(shannons: u64) -> String {
    let int_part = shannons / 100_000_000;
    let frac_part = shannons % 100_000_000;
    if frac_part == 0 {
        format!("{}", int_part)
    } else {
        format!("{}.{:08}", int_part, frac_part)
            .trim_end_matches('0')
            .to_string()
    }
}
