use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
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

pub struct SettingsComponent {
    action_tx: UnboundedSender<Action>,
    pub current_network: String,
    pub selected_index: usize,
    list_state: ListState,
}

impl SettingsComponent {
    pub fn new(action_tx: UnboundedSender<Action>, current_network: &str) -> Self {
        let mut list_state = ListState::default();
        // Find index of current network
        let selected_index = NETWORKS
            .iter()
            .position(|(name, _, _)| *name == current_network)
            .unwrap_or(0);
        list_state.select(Some(selected_index));

        Self {
            action_tx,
            current_network: current_network.to_string(),
            selected_index,
            list_state,
        }
    }

    pub fn set_network(&mut self, network: &str) {
        self.current_network = network.to_string();
        self.selected_index = NETWORKS
            .iter()
            .position(|(name, _, _)| *name == network)
            .unwrap_or(0);
        self.list_state.select(Some(self.selected_index));
    }

    fn next(&mut self) {
        let i = if self.selected_index >= NETWORKS.len() - 1 {
            0
        } else {
            self.selected_index + 1
        };
        self.selected_index = i;
        self.list_state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = if self.selected_index == 0 {
            NETWORKS.len() - 1
        } else {
            self.selected_index - 1
        };
        self.selected_index = i;
        self.list_state.select(Some(i));
    }

    fn select_network(&self) -> Result<()> {
        let (name, _, _) = NETWORKS[self.selected_index];
        if name != self.current_network {
            self.action_tx
                .send(Action::SwitchNetwork(name.to_string()))?;
        }
        Ok(())
    }

    /// Static draw method for use in App's draw_ui
    pub fn draw_static(f: &mut Frame, area: Rect, current_network: &str, selected_index: usize) {
        let chunks = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        // Network list with hotkey hints
        let hotkeys = ["[T]estnet", "[M]ainnet", "[L]ocal"];
        let items: Vec<ListItem> = NETWORKS
            .iter()
            .enumerate()
            .map(|(i, (name, _, _url))| {
                let is_current = *name == current_network;
                let is_selected = i == selected_index;

                let style = if is_selected {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else if is_current {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::White)
                };

                let marker = if is_current { " ✓" } else { "" };
                let content = Line::from(vec![Span::styled(
                    format!("{}{}", hotkeys[i], marker),
                    style,
                )]);
                ListItem::new(content)
            })
            .collect();

        let mut list_state = ListState::default();
        list_state.select(Some(selected_index));

        let list = List::new(items)
            .block(
                Block::default()
                    .title("Network Selection")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        f.render_stateful_widget(list, chunks[0], &mut list_state);

        // Network details panel
        let (name, display_name, url) = NETWORKS[selected_index];
        let is_devnet = name == "devnet";

        let mut details = vec![
            Line::from(vec![
                Span::styled("Network: ", Style::default().fg(Color::DarkGray)),
                Span::styled(display_name, Style::default().fg(Color::White)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("RPC URL: ", Style::default().fg(Color::DarkGray)),
                Span::styled(url, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(""),
        ];

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
            details.push(Line::from(""));
            details.push(Line::from(vec![Span::styled(
                "Requires local CKB devnet running",
                Style::default().fg(Color::Yellow),
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
        details.push(Line::from(""));

        let action_hint = if name == current_network {
            "[Currently active]"
        } else {
            "[Enter] Switch to this network"
        };
        details.push(Line::from(vec![Span::styled(
            action_hint,
            Style::default().fg(Color::DarkGray),
        )]));

        let details_widget = Paragraph::new(details).block(
            Block::default()
                .title("Network Details")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

        f.render_widget(details_widget, chunks[1]);
    }
}

impl Component for SettingsComponent {
    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.next();
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.previous();
            }
            KeyCode::Char('t') => {
                self.selected_index = 0;
                self.list_state.select(Some(0));
                self.select_network()?;
            }
            KeyCode::Char('m') => {
                self.selected_index = 1;
                self.list_state.select(Some(1));
                self.select_network()?;
            }
            KeyCode::Char('l') => {
                self.selected_index = 2;
                self.list_state.select(Some(2));
                self.select_network()?;
            }
            KeyCode::Enter => {
                self.select_network()?;
            }
            _ => {}
        }
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame, area: Rect) {
        Self::draw_static(f, area, &self.current_network, self.selected_index);
    }
}
