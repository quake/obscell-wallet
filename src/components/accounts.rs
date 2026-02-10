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
    is_mainnet: bool,
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
            is_mainnet: false,
        }
    }

    pub fn set_is_mainnet(&mut self, is_mainnet: bool) {
        self.is_mainnet = is_mainnet;
    }

    pub fn set_accounts(&mut self, accounts: Vec<Account>) {
        self.accounts = accounts;
        if !self.accounts.is_empty() && self.selected_index >= self.accounts.len() {
            self.selected_index = self.accounts.len() - 1;
        }
        self.list_state.select(Some(self.selected_index));
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
        is_mainnet: bool,
    ) {
        let chunks = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

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
                    .title("Accounts [n]New [i]Import [r]Rescan [R]Full")
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

        // Account details
        let details = if let Some(acc) = accounts.get(selected_index) {
            let stealth_addr = acc.stealth_address();
            let ckb_addr = acc.one_time_ckb_address(is_mainnet);

            vec![
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
                Line::from(vec![Span::styled(
                    ckb_addr,
                    Style::default().fg(Color::Cyan),
                )]),
                Line::from(""),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "[Enter] Select  [e] Export Private Key",
                    Style::default().fg(Color::DarkGray),
                )]),
            ]
        } else {
            vec![
                Line::from("No account selected"),
                Line::from(""),
                Line::from("Press [n] to create a new account"),
                Line::from("Press [i] to import an existing account"),
            ]
        };

        let details_widget = Paragraph::new(details).block(
            Block::default()
                .title("Account Details")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

        f.render_widget(details_widget, chunks[1]);
    }
}

impl Component for AccountsComponent {
    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.next();
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.previous();
            }
            KeyCode::Char('n') | KeyCode::Char('c') => {
                self.action_tx.send(Action::CreateAccount)?;
            }
            KeyCode::Char('i') => {
                self.action_tx.send(Action::ImportAccount)?;
            }
            KeyCode::Char('e') => {
                self.action_tx.send(Action::ExportAccount)?;
            }
            KeyCode::Enter => {
                self.action_tx
                    .send(Action::SelectAccount(self.selected_index))?;
            }
            KeyCode::Char('r') => {
                self.action_tx.send(Action::Rescan)?;
            }
            KeyCode::Char('R') => {
                self.action_tx.send(Action::FullRescan)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame, area: Rect) {
        let chunks = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        // Account list
        let items: Vec<ListItem> = self
            .accounts
            .iter()
            .enumerate()
            .map(|(i, acc)| {
                let style = if i == self.selected_index {
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

        let list = List::new(items)
            .block(
                Block::default()
                    .title("Accounts [n]New [i]Import [r]Rescan [R]Full")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        f.render_stateful_widget(list, chunks[0], &mut self.list_state);

        // Account details
        let details = if let Some(acc) = self.accounts.get(self.selected_index) {
            let stealth_addr = acc.stealth_address();
            let ckb_addr = acc.one_time_ckb_address(self.is_mainnet);

            vec![
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
                Line::from(vec![Span::styled(
                    ckb_addr,
                    Style::default().fg(Color::Cyan),
                )]),
                Line::from(""),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "[Enter] Select  [e] Export Private Key",
                    Style::default().fg(Color::DarkGray),
                )]),
            ]
        } else {
            vec![
                Line::from("No account selected"),
                Line::from(""),
                Line::from("Press [n] to create a new account"),
                Line::from("Press [i] to import an existing account"),
            ]
        };

        let details_widget = Paragraph::new(details).block(
            Block::default()
                .title("Account Details")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

        f.render_widget(details_widget, chunks[1]);
    }
}

fn format_ckb_balance(shannon: u64) -> String {
    let ckb = shannon / 100_000_000;
    let frac = shannon % 100_000_000;
    format!("{}.{:08} CKB", ckb, frac)
}
