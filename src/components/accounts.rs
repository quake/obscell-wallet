use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{action::Action, domain::account::Account, tui::Frame};

use super::Component;

pub struct AccountsComponent {
    action_tx: UnboundedSender<Action>,
    pub accounts: Vec<Account>,
    list_state: ListState,
    pub selected_index: usize,
}

impl AccountsComponent {
    pub fn new(action_tx: UnboundedSender<Action>) -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            action_tx,
            accounts: Vec::new(),
            list_state,
            selected_index: 0,
        }
    }

    pub fn set_accounts(&mut self, accounts: Vec<Account>) {
        self.accounts = accounts;
        if !self.accounts.is_empty() {
            if self.selected_index >= self.accounts.len() {
                self.selected_index = self.accounts.len() - 1;
            }
            self.list_state.select(Some(self.selected_index));
        }
    }

    /// Select an account by index.
    pub fn select(&mut self, index: usize) {
        if index < self.accounts.len() {
            self.selected_index = index;
            self.list_state.select(Some(index));
        }
    }

    fn next(&mut self) {
        if self.accounts.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.accounts.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.selected_index = i;
        self.list_state.select(Some(i));
    }

    fn previous(&mut self) {
        if self.accounts.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.accounts.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.selected_index = i;
        self.list_state.select(Some(i));
    }

    /// Static draw method that doesn't require mutable self reference.
    /// Used to avoid borrow checker issues with the main app draw loop.
    pub fn draw_static(
        f: &mut Frame,
        area: Rect,
        accounts: &[Account],
        selected_index: usize,
        one_time_address: Option<&str>,
        is_spinning: bool,
        network_name: Option<&str>,
    ) {
        let chunks = Layout::horizontal([Constraint::Length(40), Constraint::Min(0)]).split(area);

        // Helper to truncate string to fit width (accounting for borders)
        let max_width = chunks[1].width.saturating_sub(2) as usize;
        let truncate = |s: &str| -> String {
            if s.chars().count() <= max_width {
                s.to_string()
            } else if max_width <= 3 {
                ".".repeat(max_width)
            } else {
                let chars: Vec<char> = s.chars().collect();
                let truncated: String = chars[..max_width - 3].iter().collect();
                format!("{}...", truncated)
            }
        };

        // Account list
        let items: Vec<ListItem> = accounts
            .iter()
            .enumerate()
            .map(|(i, acc)| {
                let style = if i == selected_index {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                let balance_str = format_ckb_balance(acc.ckb_balance);
                let content = Line::from(vec![
                    Span::styled(&acc.name, style),
                    Span::raw(" - "),
                    Span::styled(balance_str, Style::default().fg(Color::Green)),
                ]);
                ListItem::new(content)
            })
            .collect();

        let mut list_state = ListState::default();
        list_state.select(Some(selected_index));

        let list = List::new(items)
            .block(
                Block::default()
                    .title("Accounts")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        f.render_stateful_widget(list, chunks[0], &mut list_state);

        // Right side: Account details with help at bottom
        let right_chunks =
            Layout::vertical([Constraint::Min(0), Constraint::Length(3)]).split(chunks[1]);

        // Account details
        let details = if let Some(acc) = accounts.get(selected_index) {
            let stealth_addr = truncate(&acc.stealth_address());
            let ckb_addr = one_time_address
                .map(&truncate)
                .unwrap_or_else(|| "(generating...)".to_string());

            // Address style - blinking effect when spinning
            let addr_style = if is_spinning {
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::RAPID_BLINK)
            } else {
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD)
            };

            // Status text based on spinning state
            let status_lines = if is_spinning {
                vec![Line::from(vec![Span::styled(
                    "Rotating... Press Enter to select",
                    Style::default().fg(Color::Yellow),
                )])]
            } else {
                let mut lines = vec![Line::from(vec![Span::styled(
                    "Address selected! Press Enter to regenerate",
                    Style::default().fg(Color::Green),
                )])];
                // Show faucet hint for testnet
                if network_name == Some("testnet") {
                    lines.push(Line::from(""));
                    lines.push(Line::from(vec![Span::styled(
                        "Get test CKB from: https://faucet.nervos.org/",
                        Style::default().fg(Color::Cyan),
                    )]));
                }
                lines
            };

            let mut details = vec![
                Line::from(vec![
                    Span::styled("Name: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(&acc.name, Style::default().fg(Color::White)),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("CKB Balance: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format_ckb_balance(acc.ckb_balance),
                        Style::default().fg(Color::Green),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Stealth Address (for receiving):",
                    Style::default().fg(Color::DarkGray),
                )]),
                Line::from(vec![Span::styled(
                    stealth_addr,
                    Style::default().fg(Color::Yellow),
                )]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "One-time CKB Address:",
                    Style::default().fg(Color::DarkGray),
                )]),
                Line::from(vec![Span::styled(ckb_addr, addr_style)]),
                Line::from(""),
            ];
            details.extend(status_lines);
            details
        } else {
            vec![
                Line::from(vec![Span::styled(
                    "No accounts yet",
                    Style::default().fg(Color::Yellow),
                )]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Go to Settings (G) to create a new account.",
                    Style::default().fg(Color::DarkGray),
                )]),
            ]
        };

        let details_widget = Paragraph::new(details).block(
            Block::default()
                .title("Account Details")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

        f.render_widget(details_widget, right_chunks[0]);

        // Help text
        let help_text = Line::from(Span::styled(
            "Up/Down: Navigate | Enter: Select/Regenerate address",
            Style::default().fg(Color::DarkGray),
        ));

        let help_widget = Paragraph::new(help_text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

        f.render_widget(help_widget, right_chunks[1]);
    }
}

impl Component for AccountsComponent {
    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Down => {
                self.next();
                // Auto-select account on navigation
                if !self.accounts.is_empty() {
                    self.action_tx
                        .send(Action::SelectAccount(self.selected_index))?;
                }
            }
            KeyCode::Up => {
                self.previous();
                // Auto-select account on navigation
                if !self.accounts.is_empty() {
                    self.action_tx
                        .send(Action::SelectAccount(self.selected_index))?;
                }
            }
            KeyCode::Enter => {
                // Toggle one-time address spinning
                self.action_tx.send(Action::ToggleAddressSpinning)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame, area: Rect) {
        Self::draw_static(
            f,
            area,
            &self.accounts,
            self.selected_index,
            None, // one_time_address is managed by ReceiveComponent
            true, // is_spinning default to true
            None, // network_name not available here
        );
    }
}

fn format_ckb_balance(shannon: u64) -> String {
    let ckb = shannon / 100_000_000;
    let frac = shannon % 100_000_000;
    format!("{}.{:08} CKB", ckb, frac)
}
