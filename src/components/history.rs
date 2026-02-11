//! Transaction history component.

use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};

use crate::{
    domain::{
        account::Account,
        cell::{TxRecord, TxStatus, TxType},
    },
    tui::Frame,
};

use super::Component;

/// History component for displaying transaction history.
pub struct HistoryComponent {
    pub account: Option<Account>,
    pub transactions: Vec<TxRecord>,
    list_state: ListState,
    selected_index: usize,
}

impl HistoryComponent {
    pub fn new() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            account: None,
            transactions: Vec::new(),
            list_state,
            selected_index: 0,
        }
    }

    pub fn set_account(&mut self, account: Option<Account>) {
        self.account = account;
    }

    pub fn set_transactions(&mut self, transactions: Vec<TxRecord>) {
        self.transactions = transactions;
        if !self.transactions.is_empty() && self.selected_index >= self.transactions.len() {
            self.selected_index = self.transactions.len() - 1;
        }
        self.list_state.select(Some(self.selected_index));
    }

    fn next(&mut self) {
        if self.transactions.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.transactions.len() - 1 {
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
        if self.transactions.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.transactions.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.selected_index = i;
        self.list_state.select(Some(i));
    }

    /// Format a timestamp as a human-readable date/time.
    fn format_timestamp(timestamp: i64) -> String {
        use std::time::{Duration, UNIX_EPOCH};

        let datetime = UNIX_EPOCH + Duration::from_secs(timestamp as u64);
        let now = std::time::SystemTime::now();

        // Calculate elapsed time
        if let Ok(elapsed) = now.duration_since(datetime) {
            let secs = elapsed.as_secs();
            if secs < 60 {
                return "just now".to_string();
            } else if secs < 3600 {
                let mins = secs / 60;
                return format!("{} min ago", mins);
            } else if secs < 86400 {
                let hours = secs / 3600;
                return format!("{} hours ago", hours);
            } else if secs < 604800 {
                let days = secs / 86400;
                return format!("{} days ago", days);
            }
        }

        // Fall back to raw timestamp
        format!("{}", timestamp)
    }

    /// Static draw method for use in app.rs draw loop.
    pub fn draw_static(
        f: &mut Frame,
        area: Rect,
        transactions: &[TxRecord],
        selected_index: usize,
        account: Option<&Account>,
    ) {
        let chunks = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Transaction list
        let items: Vec<ListItem> = transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                let style = if i == selected_index {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                let direction = tx.direction();
                let direction_color = match &tx.tx_type {
                    TxType::StealthSend { .. } => Color::Red,
                    TxType::StealthReceive { .. } => Color::Green,
                    TxType::CkbSend { .. } => Color::Red,
                    TxType::CtTransfer { .. } => Color::Yellow,
                    TxType::CtMint { .. } => Color::Magenta,
                    TxType::CtGenesis { .. } => Color::Cyan,
                };

                let amount_str = tx
                    .amount_ckb()
                    .map(|a| format!("{:.8} CKB", a))
                    .unwrap_or_else(|| "CT".to_string());

                let status_indicator = match tx.status {
                    TxStatus::Pending => "...",
                    TxStatus::Confirmed => " ",
                    TxStatus::Failed => "X ",
                };

                let content = Line::from(vec![
                    Span::styled(status_indicator, Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{:<8}", direction),
                        Style::default().fg(direction_color),
                    ),
                    Span::styled(amount_str, style),
                    Span::raw(" "),
                    Span::styled(
                        Self::format_timestamp(tx.timestamp),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]);
                ListItem::new(content)
            })
            .collect();

        let mut list_state = ListState::default();
        list_state.select(Some(selected_index));

        let title = account
            .map(|a| format!("History - {}", a.name))
            .unwrap_or_else(|| "History".to_string());

        let list = List::new(items)
            .block(
                Block::default()
                    .title(title)
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

        // Transaction details
        let details = if let Some(tx) = transactions.get(selected_index) {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("Type: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(tx.direction(), Style::default().fg(Color::White)),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Status: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{:?}", tx.status),
                        Style::default().fg(match tx.status {
                            TxStatus::Pending => Color::Yellow,
                            TxStatus::Confirmed => Color::Green,
                            TxStatus::Failed => Color::Red,
                        }),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("TX Hash: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(tx.short_hash(), Style::default().fg(Color::Cyan)),
                ]),
                Line::from(""),
            ];

            // Add amount
            if let Some(amount) = tx.amount_ckb() {
                lines.push(Line::from(vec![
                    Span::styled("Amount: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{:.8} CKB", amount),
                        Style::default().fg(Color::Green),
                    ),
                ]));
                lines.push(Line::from(""));
            }

            // Add recipient for sends
            if let TxType::StealthSend { to, .. } | TxType::CkbSend { to, .. } = &tx.tx_type {
                lines.push(Line::from(vec![Span::styled(
                    "Recipient:",
                    Style::default().fg(Color::DarkGray),
                )]));
                // Show truncated address
                let truncated = if to.len() > 40 {
                    format!("{}...{}", &to[..20], &to[to.len() - 16..])
                } else {
                    to.clone()
                };
                lines.push(Line::from(vec![Span::styled(
                    truncated,
                    Style::default().fg(Color::Yellow),
                )]));
                lines.push(Line::from(""));
            }

            // Add block number if confirmed
            if let Some(block) = tx.block_number {
                lines.push(Line::from(vec![
                    Span::styled("Block: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(format!("{}", block), Style::default().fg(Color::White)),
                ]));
                lines.push(Line::from(""));
            }

            // Add timestamp
            lines.push(Line::from(vec![
                Span::styled("Time: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    Self::format_timestamp(tx.timestamp),
                    Style::default().fg(Color::White),
                ),
            ]));

            lines
        } else {
            vec![
                Line::from("No transaction selected"),
                Line::from(""),
                Line::from("Use Up/Down to navigate"),
            ]
        };

        let details_widget = Paragraph::new(details).block(
            Block::default()
                .title("Transaction Details")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

        f.render_widget(details_widget, chunks[1]);
    }
}

impl Default for HistoryComponent {
    fn default() -> Self {
        Self::new()
    }
}

impl Component for HistoryComponent {
    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Down => {
                self.next();
            }
            KeyCode::Up => {
                self.previous();
            }
            _ => {}
        }
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame, area: Rect) {
        Self::draw_static(
            f,
            area,
            &self.transactions,
            self.selected_index,
            self.account.as_ref(),
        );
    }
}
