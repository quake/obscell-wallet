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

            vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "One-Time CKB Address (for direct CKB sends):",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
                // Display address on single line for easy copying
                Line::from(vec![Span::styled(
                    addr_display,
                    Style::default().fg(Color::Magenta),
                )]),
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
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that CKB address is generated in correct bech32m format.
    /// Format should be: ckb1... (mainnet) or ckt1... (testnet)
    /// where "1" is the bech32 separator.
    #[test]
    fn test_ckb_address_format() {
        // Use the RFC example to verify our address generation
        let code_hash_hex = "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
        let code_hash_bytes = hex::decode(code_hash_hex).unwrap();
        let code_hash = Byte32::from_slice(&code_hash_bytes).unwrap();

        let args_hex = "b39bbc0b3673c7d36450bc14cfcdad2d559c6c64";
        let args = hex::decode(args_hex).unwrap();

        let payload = AddressPayload::new_full(ScriptHashType::Type, code_hash, args.into());

        // Test mainnet address
        let mainnet_addr = payload.display_with_network(NetworkType::Mainnet, true);
        assert!(
            mainnet_addr.starts_with("ckb1"),
            "Mainnet address should start with 'ckb1', got: {}",
            mainnet_addr
        );
        // Verify against RFC example
        assert_eq!(
            mainnet_addr,
            "ckb1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqdnnw7qkdnnclfkg59uzn8umtfd2kwxceqxwquc4"
        );

        // Test testnet address
        let testnet_addr = payload.display_with_network(NetworkType::Testnet, true);
        assert!(
            testnet_addr.starts_with("ckt1"),
            "Testnet address should start with 'ckt1', got: {}",
            testnet_addr
        );
    }

    /// Test that receive component uses the correct code hash from config.
    #[test]
    fn test_receive_uses_config_code_hash() {
        use crate::config::Config;
        use ckb_sdk::Address;
        use std::str::FromStr;
        use tokio::sync::mpsc;

        let (action_tx, _action_rx) = mpsc::unbounded_channel();
        let mut receive = ReceiveComponent::new(action_tx);

        // Load devnet config (should come from config/devnet.toml)
        let config = Config::from_network("devnet");
        let expected_code_hash = config.contracts.stealth_lock_code_hash.clone();

        println!("Using stealth_lock_code_hash: {}", expected_code_hash);

        // Verify it's NOT the testnet code hash
        let testnet_code_hash =
            "0x1d7f12a173ed22df9de1180a0b11e2a4368568017d9cfdfb5658b50c147549d6";
        assert_ne!(
            expected_code_hash, testnet_code_hash,
            "Config should NOT be using testnet code hash"
        );

        // Set config
        receive.set_config(config);

        // Create a test account
        let account = crate::domain::account::Account::new(1, "test".to_string());
        receive.set_account(Some(account));

        // Verify address was generated
        let address = receive
            .one_time_address
            .as_ref()
            .expect("Address should be generated");
        println!("Generated address: {}", address);

        // Parse the address to extract the code hash
        let parsed = Address::from_str(address).expect("Should parse address");
        let payload = parsed.payload();

        // Get the code hash from the payload - Full variant has named fields
        match payload {
            AddressPayload::Full {
                code_hash, args, ..
            } => {
                let code_hash_in_addr = hex::encode(code_hash.as_slice());
                println!("Code hash in address: 0x{}", code_hash_in_addr);
                println!("Args length: {}", args.len());

                // Verify it matches the devnet config
                let expected_without_prefix = expected_code_hash
                    .strip_prefix("0x")
                    .unwrap_or(&expected_code_hash);
                assert_eq!(
                    code_hash_in_addr, expected_without_prefix,
                    "Address should contain devnet code hash, not testnet"
                );
            }
            _ => panic!("Expected Full address payload"),
        }
    }
}
