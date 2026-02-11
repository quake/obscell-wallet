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

/// Focus state within Accounts view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountsFocus {
    /// Focus on account list.
    List,
    /// Focus on operation menu.
    Operations,
}

/// Available operations in Accounts view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountOperation {
    Select,
    Create,
    Import,
    Export,
}

impl AccountOperation {
    fn all() -> &'static [AccountOperation] {
        &[
            AccountOperation::Select,
            AccountOperation::Create,
            AccountOperation::Import,
            AccountOperation::Export,
        ]
    }

    fn label(&self) -> &'static str {
        match self {
            AccountOperation::Select => "Select Account",
            AccountOperation::Create => "Create New Account",
            AccountOperation::Import => "Import Account",
            AccountOperation::Export => "Export Private Key",
        }
    }
}

pub struct AccountsComponent {
    action_tx: UnboundedSender<Action>,
    pub accounts: Vec<Account>,
    list_state: ListState,
    pub selected_index: usize,
    pub focus: AccountsFocus,
    pub selected_operation: usize,
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
            focus: AccountsFocus::List,
            selected_operation: 0,
            is_mainnet: false,
        }
    }

    pub fn set_is_mainnet(&mut self, is_mainnet: bool) {
        self.is_mainnet = is_mainnet;
    }

    pub fn set_accounts(&mut self, accounts: Vec<Account>) {
        let was_empty = self.accounts.is_empty();
        self.accounts = accounts;
        if self.accounts.is_empty() {
            // Auto-focus Operations menu when list is empty
            self.focus = AccountsFocus::Operations;
        } else {
            // Reset focus to List when accounts become available
            // (e.g., after creating first account)
            if was_empty {
                self.focus = AccountsFocus::List;
            }
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
    #[allow(clippy::too_many_arguments)]
    pub fn draw_static(
        f: &mut Frame,
        area: Rect,
        accounts: &[Account],
        selected_index: usize,
        focus: AccountsFocus,
        selected_operation: usize,
        is_mainnet: bool,
    ) {
        let chunks = Layout::horizontal([Constraint::Length(35), Constraint::Min(0)]).split(area);

        // Left side: split into account list and operations menu
        let left_chunks =
            Layout::vertical([Constraint::Min(0), Constraint::Length(8)]).split(chunks[0]);

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

        let list_border_color = if focus == AccountsFocus::List {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let list = List::new(items)
            .block(
                Block::default()
                    .title("Accounts")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(list_border_color)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        f.render_stateful_widget(list, left_chunks[0], &mut list_state);

        // Operations menu
        let ops = AccountOperation::all();
        let op_items: Vec<ListItem> = ops
            .iter()
            .enumerate()
            .map(|(i, op)| {
                let style = if i == selected_operation && focus == AccountsFocus::Operations {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(Line::from(Span::styled(op.label(), style)))
            })
            .collect();

        let mut op_state = ListState::default();
        if focus == AccountsFocus::Operations {
            op_state.select(Some(selected_operation));
        }

        let ops_border_color = if focus == AccountsFocus::Operations {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let ops_list = List::new(op_items)
            .block(
                Block::default()
                    .title("Operations")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(ops_border_color)),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        f.render_stateful_widget(ops_list, left_chunks[1], &mut op_state);

        // Right side: Account details with help at bottom
        let right_chunks =
            Layout::vertical([Constraint::Min(0), Constraint::Length(3)]).split(chunks[1]);

        // Account details
        let details = if let Some(acc) = accounts.get(selected_index) {
            let stealth_addr = truncate(&acc.stealth_address());
            let ckb_addr = truncate(&acc.one_time_ckb_address(is_mainnet));

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
            ]
        } else {
            vec![
                Line::from("No accounts yet"),
                Line::from(""),
                Line::from("Select 'Create New Account' or"),
                Line::from("'Import Account' from the menu."),
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
            "Up/Down: Navigate | Enter: Select/Execute",
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
        let ops = AccountOperation::all();
        match self.focus {
            AccountsFocus::List => match key.code {
                KeyCode::Down => {
                    // If at last item or list is empty, move to Operations
                    if self.accounts.is_empty()
                        || self.selected_index >= self.accounts.len().saturating_sub(1)
                    {
                        self.focus = AccountsFocus::Operations;
                        self.selected_operation = 0;
                    } else {
                        self.next();
                    }
                }
                KeyCode::Up => {
                    // If at first item, wrap to Operations (bottom)
                    if self.selected_index == 0 {
                        self.focus = AccountsFocus::Operations;
                        self.selected_operation = ops.len() - 1;
                    } else {
                        self.previous();
                    }
                }
                KeyCode::Enter => {
                    // Select the current account
                    if !self.accounts.is_empty() {
                        self.action_tx
                            .send(Action::SelectAccount(self.selected_index))?;
                    }
                }
                _ => {}
            },
            AccountsFocus::Operations => match key.code {
                KeyCode::Down => {
                    // If at last operation, wrap to List (top)
                    if self.selected_operation >= ops.len() - 1 {
                        if !self.accounts.is_empty() {
                            self.focus = AccountsFocus::List;
                            self.selected_index = 0;
                            self.list_state.select(Some(0));
                        } else {
                            // Wrap within operations if list is empty
                            self.selected_operation = 0;
                        }
                    } else {
                        self.selected_operation += 1;
                    }
                }
                KeyCode::Up => {
                    // If at first operation, move to List (bottom)
                    if self.selected_operation == 0 {
                        if !self.accounts.is_empty() {
                            self.focus = AccountsFocus::List;
                            self.selected_index = self.accounts.len() - 1;
                            self.list_state.select(Some(self.selected_index));
                        } else {
                            // Wrap within operations if list is empty
                            self.selected_operation = ops.len() - 1;
                        }
                    } else {
                        self.selected_operation -= 1;
                    }
                }
                KeyCode::Enter => match ops[self.selected_operation] {
                    AccountOperation::Select => {
                        if !self.accounts.is_empty() {
                            self.action_tx
                                .send(Action::SelectAccount(self.selected_index))?;
                        }
                    }
                    AccountOperation::Create => {
                        self.action_tx.send(Action::CreateAccount)?;
                    }
                    AccountOperation::Import => {
                        self.action_tx.send(Action::ImportAccount)?;
                    }
                    AccountOperation::Export => {
                        self.action_tx.send(Action::ExportAccount)?;
                    }
                },
                _ => {}
            },
        }
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame, area: Rect) {
        Self::draw_static(
            f,
            area,
            &self.accounts,
            self.selected_index,
            self.focus,
            self.selected_operation,
            self.is_mainnet,
        );
    }
}

fn format_ckb_balance(shannon: u64) -> String {
    let ckb = shannon / 100_000_000;
    let frac = shannon % 100_000_000;
    format!("{}.{:08} CKB", ckb, frac)
}
