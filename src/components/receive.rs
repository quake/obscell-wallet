//! Receive component for displaying stealth addresses and generating fresh addresses.

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

/// Component for receiving funds via stealth addresses.
pub struct ReceiveComponent {
    action_tx: UnboundedSender<Action>,
    pub account: Option<Account>,
    /// One-time address that is regenerated on demand
    pub one_time_address: Option<String>,
    /// Stealth script args for the one-time address
    pub script_args: Option<String>,
}

impl ReceiveComponent {
    pub fn new(action_tx: UnboundedSender<Action>) -> Self {
        Self {
            action_tx,
            account: None,
            one_time_address: None,
            script_args: None,
        }
    }

    /// Set the current account to show receive info for.
    pub fn set_account(&mut self, account: Option<Account>) {
        self.account = account;
        self.regenerate_address();
    }

    /// Generate a fresh one-time address.
    pub fn regenerate_address(&mut self) {
        if let Some(ref account) = self.account {
            // Generate ephemeral key and stealth pubkey
            let view_pub = account.view_public_key();
            let spend_pub = account.spend_public_key();

            let (eph_pub, stealth_pub) =
                crate::domain::stealth::generate_ephemeral_key(&view_pub, &spend_pub);

            // Build script args: ephemeral_pubkey (33B) || pubkey_hash (20B)
            let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
            let script_args = [eph_pub.serialize().as_slice(), &pubkey_hash[0..20]].concat();

            self.script_args = Some(hex::encode(&script_args));
            self.one_time_address = Some(format!("0x{}", hex::encode(&script_args)));
        } else {
            self.one_time_address = None;
            self.script_args = None;
        }
    }

    /// Static draw method for use in the main app draw loop.
    pub fn draw_static(
        f: &mut Frame,
        area: Rect,
        account: Option<&Account>,
        one_time_address: Option<&str>,
        script_args: Option<&str>,
    ) {
        let chunks = Layout::vertical([Constraint::Length(12), Constraint::Min(0)]).split(area);

        // Stealth address info
        let stealth_info = if let Some(acc) = account {
            let stealth_addr = acc.stealth_address();

            vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("Account: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&acc.name, Style::default().fg(Color::White)),
                ]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Stealth Address (share with senders):",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    format!("  {}", &stealth_addr[..66]),
                    Style::default().fg(Color::Cyan),
                )]),
                Line::from(vec![Span::styled(
                    format!("  {}", &stealth_addr[66..]),
                    Style::default().fg(Color::Cyan),
                )]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "This address can be reused. Senders will derive unique one-time addresses.",
                    Style::default().fg(Color::DarkGray),
                )]),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "No account selected. Create or select an account first.",
                    Style::default().fg(Color::Red),
                )]),
            ]
        };

        let stealth_widget = Paragraph::new(stealth_info).block(
            Block::default()
                .title("Stealth Address")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(stealth_widget, chunks[0]);

        // One-time address info
        let one_time_info = if account.is_some() {
            let addr_display = one_time_address.unwrap_or("Press [g] to generate");
            let args_display = script_args.unwrap_or("");

            vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "One-Time Address (for direct CKB sends):",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Script Args:",
                    Style::default().fg(Color::DarkGray),
                )]),
                Line::from(vec![Span::styled(
                    format!(
                        "  {}",
                        if args_display.len() > 60 {
                            &args_display[..60]
                        } else {
                            args_display
                        }
                    ),
                    Style::default().fg(Color::Green),
                )]),
                if args_display.len() > 60 {
                    Line::from(vec![Span::styled(
                        format!("  {}", &args_display[60..]),
                        Style::default().fg(Color::Green),
                    )])
                } else {
                    Line::from("")
                },
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Full One-Time Address:",
                    Style::default().fg(Color::DarkGray),
                )]),
                Line::from(vec![Span::styled(
                    format!(
                        "  {}",
                        if addr_display.len() > 70 {
                            &addr_display[..70]
                        } else {
                            addr_display
                        }
                    ),
                    Style::default().fg(Color::Magenta),
                )]),
                if addr_display.len() > 70 {
                    Line::from(vec![Span::styled(
                        format!("  {}", &addr_display[70..]),
                        Style::default().fg(Color::Magenta),
                    )])
                } else {
                    Line::from("")
                },
                Line::from(""),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "[g] Generate new one-time address",
                    Style::default().fg(Color::DarkGray),
                )]),
                Line::from(vec![Span::styled(
                    "Each one-time address should only be used once for privacy.",
                    Style::default().fg(Color::DarkGray),
                )]),
            ]
        } else {
            vec![]
        };

        let one_time_widget = Paragraph::new(one_time_info).block(
            Block::default()
                .title("One-Time Address")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(one_time_widget, chunks[1]);
    }
}

impl Component for ReceiveComponent {
    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        if let KeyCode::Char('g') = key.code {
            // Generate a new one-time address
            self.regenerate_address();
        }
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame, area: Rect) {
        Self::draw_static(
            f,
            area,
            self.account.as_ref(),
            self.one_time_address.as_deref(),
            self.script_args.as_deref(),
        );
    }
}
