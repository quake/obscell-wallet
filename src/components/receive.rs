//! Receive component for displaying stealth addresses and generating fresh addresses.

use ckb_sdk::{AddressPayload, NetworkType};
use ckb_types::core::ScriptHashType;
use ckb_types::packed::Byte32;
use ckb_types::prelude::*;
use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{action::Action, config::Config, domain::account::Account, tui::Frame};

use super::Component;

/// Component for receiving funds via stealth addresses.
pub struct ReceiveComponent {
    action_tx: UnboundedSender<Action>,
    pub account: Option<Account>,
    /// One-time CKB address (ckb1.../ckt1...)
    pub one_time_address: Option<String>,
    /// Config for network and contract info
    config: Option<Config>,
}

impl ReceiveComponent {
    pub fn new(action_tx: UnboundedSender<Action>) -> Self {
        Self {
            action_tx,
            account: None,
            one_time_address: None,
            config: None,
        }
    }

    /// Set the config for network and contract info.
    pub fn set_config(&mut self, config: Config) {
        self.config = Some(config);
        self.regenerate_address();
    }

    /// Set the current account to show receive info for.
    pub fn set_account(&mut self, account: Option<Account>) {
        self.account = account;
        self.regenerate_address();
    }

    /// Generate a fresh one-time address in proper CKB format.
    pub fn regenerate_address(&mut self) {
        let Some(ref account) = self.account else {
            self.one_time_address = None;
            return;
        };
        let Some(ref config) = self.config else {
            self.one_time_address = None;
            return;
        };

        // Generate ephemeral key and stealth pubkey
        let view_pub = account.view_public_key();
        let spend_pub = account.spend_public_key();

        let (eph_pub, stealth_pub) =
            crate::domain::stealth::generate_ephemeral_key(&view_pub, &spend_pub);

        // Build script args: ephemeral_pubkey (33B) || pubkey_hash (20B)
        let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
        let script_args = [eph_pub.serialize().as_slice(), &pubkey_hash[0..20]].concat();

        // Get stealth lock code hash from config
        let code_hash_hex = config
            .contracts
            .stealth_lock_code_hash
            .strip_prefix("0x")
            .unwrap_or(&config.contracts.stealth_lock_code_hash);
        let code_hash_bytes =
            hex::decode(code_hash_hex).expect("Invalid stealth_lock_code_hash in config");
        let code_hash = Byte32::from_slice(&code_hash_bytes).expect("Invalid code hash length");

        // Build AddressPayload for full address format (custom script)
        let payload = AddressPayload::new_full(ScriptHashType::Type, code_hash, script_args.into());

        // Determine network type from config
        let network = match config.network.name.as_str() {
            "mainnet" | "lina" => NetworkType::Mainnet,
            _ => NetworkType::Testnet, // testnet, devnet, etc. all use ckt prefix
        };

        // Generate the address string (ckb1... or ckt1...)
        let address = payload.display_with_network(network, true);
        self.one_time_address = Some(address);
    }

    /// Static draw method for use in the main app draw loop.
    pub fn draw_static(
        f: &mut Frame,
        area: Rect,
        account: Option<&Account>,
        one_time_address: Option<&str>,
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

            // Split long address into multiple lines for display
            let addr_lines: Vec<Line> = if addr_display.len() > 60 {
                let mut lines = vec![Line::from(vec![Span::styled(
                    format!("  {}", &addr_display[..60]),
                    Style::default().fg(Color::Magenta),
                )])];
                let remaining = &addr_display[60..];
                // Split remaining into chunks of 60 chars
                for chunk in remaining.as_bytes().chunks(60) {
                    let s = std::str::from_utf8(chunk).unwrap_or("");
                    lines.push(Line::from(vec![Span::styled(
                        format!("  {}", s),
                        Style::default().fg(Color::Magenta),
                    )]));
                }
                lines
            } else {
                vec![Line::from(vec![Span::styled(
                    format!("  {}", addr_display),
                    Style::default().fg(Color::Magenta),
                )])]
            };

            let mut info = vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "One-Time CKB Address (for direct CKB sends):",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
            ];
            info.extend(addr_lines);
            info.extend(vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "[g] Generate new one-time address",
                    Style::default().fg(Color::DarkGray),
                )]),
                Line::from(vec![Span::styled(
                    "Each one-time address should only be used once for privacy.",
                    Style::default().fg(Color::DarkGray),
                )]),
            ]);
            info
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
        );
    }
}
