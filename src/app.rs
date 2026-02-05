use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Tabs},
};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tracing::{debug, info};

use crate::{
    action::Action,
    components::{accounts::AccountsComponent, Component},
    config::Config,
    domain::account::AccountManager,
    infra::store::Store,
    tui::{Event, Frame, Tui},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Accounts,
    Send,
    Receive,
    Tokens,
    History,
}

impl Tab {
    pub fn all() -> Vec<Tab> {
        vec![
            Tab::Accounts,
            Tab::Send,
            Tab::Receive,
            Tab::Tokens,
            Tab::History,
        ]
    }

    pub fn title(&self) -> &'static str {
        match self {
            Tab::Accounts => "Accounts",
            Tab::Send => "Send",
            Tab::Receive => "Receive",
            Tab::Tokens => "Tokens",
            Tab::History => "History",
        }
    }

    pub fn index(&self) -> usize {
        match self {
            Tab::Accounts => 0,
            Tab::Send => 1,
            Tab::Receive => 2,
            Tab::Tokens => 3,
            Tab::History => 4,
        }
    }

    pub fn from_index(index: usize) -> Tab {
        match index {
            0 => Tab::Accounts,
            1 => Tab::Send,
            2 => Tab::Receive,
            3 => Tab::Tokens,
            4 => Tab::History,
            _ => Tab::Accounts,
        }
    }
}

pub struct App {
    pub should_quit: bool,
    pub should_suspend: bool,
    pub config: Config,
    pub active_tab: Tab,
    pub last_tick_key_events: Vec<KeyEvent>,
    pub action_tx: UnboundedSender<Action>,
    pub action_rx: UnboundedReceiver<Action>,
    pub tui: Tui,
    pub store: Store,
    pub account_manager: AccountManager,
    pub accounts_component: AccountsComponent,
    pub status_message: String,
}

impl App {
    pub fn new(tick_rate: f64, frame_rate: f64) -> Result<Self> {
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let config = Config::default();
        let store = Store::new()?;
        let account_manager = AccountManager::new(store.clone());
        let accounts_component = AccountsComponent::new(action_tx.clone());

        let tui = Tui::new()?
            .tick_rate(tick_rate)
            .frame_rate(frame_rate)
            .mouse(false)
            .paste(false);

        Ok(Self {
            should_quit: false,
            should_suspend: false,
            config,
            active_tab: Tab::Accounts,
            last_tick_key_events: Vec::new(),
            action_tx,
            action_rx,
            tui,
            store,
            account_manager,
            accounts_component,
            status_message: "Ready".to_string(),
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        self.tui.enter()?;

        // Load accounts
        self.accounts_component
            .set_accounts(self.account_manager.list_accounts()?);

        loop {
            // Handle events
            if let Some(event) = self.tui.next().await {
                self.handle_event(event).await?;
            }

            // Handle actions
            while let Ok(action) = self.action_rx.try_recv() {
                self.handle_action(action).await?;
            }

            if self.should_suspend {
                self.tui.suspend()?;
                self.should_suspend = false;
                self.tui.resume()?;
            }

            if self.should_quit {
                break;
            }
        }

        self.tui.exit()?;
        Ok(())
    }

    async fn handle_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Tick => {
                self.action_tx.send(Action::Tick)?;
            }
            Event::Render => {
                self.draw_ui()?;
            }
            Event::Key(key_event) => {
                self.handle_key_event(key_event)?;
            }
            Event::Resize(w, h) => {
                self.action_tx.send(Action::Resize(w, h))?;
            }
            Event::Init => {
                info!("Application initialized");
            }
            Event::Quit => {
                self.should_quit = true;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        // Global key bindings
        match key.code {
            KeyCode::Char('q') if key.modifiers.is_empty() => {
                self.action_tx.send(Action::Quit)?;
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.action_tx.send(Action::Quit)?;
            }
            KeyCode::Char('z') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.action_tx.send(Action::Suspend)?;
            }
            KeyCode::Char('?') => {
                self.action_tx.send(Action::Help)?;
            }
            // Tab switching
            KeyCode::Char('1') => {
                self.active_tab = Tab::Accounts;
            }
            KeyCode::Char('2') => {
                self.active_tab = Tab::Send;
            }
            KeyCode::Char('3') => {
                self.active_tab = Tab::Receive;
            }
            KeyCode::Char('4') => {
                self.active_tab = Tab::Tokens;
            }
            KeyCode::Char('5') => {
                self.active_tab = Tab::History;
            }
            KeyCode::Tab => {
                let next_index = (self.active_tab.index() + 1) % Tab::all().len();
                self.active_tab = Tab::from_index(next_index);
            }
            KeyCode::BackTab => {
                let prev_index = if self.active_tab.index() == 0 {
                    Tab::all().len() - 1
                } else {
                    self.active_tab.index() - 1
                };
                self.active_tab = Tab::from_index(prev_index);
            }
            // Component-specific key handling
            _ => {
                match self.active_tab {
                    Tab::Accounts => {
                        self.accounts_component.handle_key_event(key)?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    async fn handle_action(&mut self, action: Action) -> Result<()> {
        debug!("Handling action: {:?}", action);
        match action {
            Action::Quit => {
                self.should_quit = true;
            }
            Action::Suspend => {
                self.should_suspend = true;
            }
            Action::CreateAccount => {
                let account = self.account_manager.create_account(
                    format!("Account {}", self.account_manager.list_accounts()?.len() + 1),
                )?;
                self.accounts_component
                    .set_accounts(self.account_manager.list_accounts()?);
                self.status_message = format!("Created account: {}", account.name);
            }
            Action::SelectAccount(index) => {
                self.account_manager.set_active_account(index)?;
                self.status_message = format!("Selected account {}", index);
            }
            Action::Rescan => {
                self.status_message = "Rescanning...".to_string();
                // TODO: Implement rescan
            }
            _ => {}
        }
        Ok(())
    }

    fn draw_ui(&mut self) -> Result<()> {
        // Collect all data needed for drawing before borrowing terminal
        let config_network_name = self.config.network.name.clone();
        let active_tab = self.active_tab;
        let status_message = self.status_message.clone();
        let accounts = self.accounts_component.accounts.clone();
        let selected_index = self.accounts_component.selected_index;

        self.tui.draw(|f| {
            let chunks = Layout::vertical([
                Constraint::Length(3), // Header
                Constraint::Length(3), // Tabs
                Constraint::Min(0),    // Content
                Constraint::Length(3), // Status
            ])
            .split(f.area());

            // Draw header
            let title = Paragraph::new(vec![Line::from(vec![
                Span::styled(
                    "Obscell Wallet",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("[{}]", config_network_name),
                    Style::default().fg(Color::Yellow),
                ),
            ])])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(title, chunks[0]);

            // Draw tabs
            let titles: Vec<Line> = Tab::all()
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    Line::from(vec![
                        Span::styled(
                            format!("[{}]", i + 1),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::raw(t.title()),
                    ])
                })
                .collect();

            let tabs = Tabs::new(titles)
                .block(Block::default().borders(Borders::ALL))
                .select(active_tab.index())
                .style(Style::default().fg(Color::White))
                .highlight_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                );
            f.render_widget(tabs, chunks[1]);

            // Draw content
            match active_tab {
                Tab::Accounts => {
                    AccountsComponent::draw_static(f, chunks[2], &accounts, selected_index);
                }
                Tab::Send => {
                    let block = Block::default()
                        .title("Send")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray));
                    let paragraph = Paragraph::new("Send view - Coming soon...")
                        .block(block)
                        .style(Style::default().fg(Color::Gray));
                    f.render_widget(paragraph, chunks[2]);
                }
                Tab::Receive => {
                    let block = Block::default()
                        .title("Receive")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray));
                    let paragraph = Paragraph::new("Receive view - Coming soon...")
                        .block(block)
                        .style(Style::default().fg(Color::Gray));
                    f.render_widget(paragraph, chunks[2]);
                }
                Tab::Tokens => {
                    let block = Block::default()
                        .title("Tokens")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray));
                    let paragraph = Paragraph::new("Tokens view - Coming soon...")
                        .block(block)
                        .style(Style::default().fg(Color::Gray));
                    f.render_widget(paragraph, chunks[2]);
                }
                Tab::History => {
                    let block = Block::default()
                        .title("History")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray));
                    let paragraph = Paragraph::new("History view - Coming soon...")
                        .block(block)
                        .style(Style::default().fg(Color::Gray));
                    f.render_widget(paragraph, chunks[2]);
                }
            }

            // Draw status
            let status = Paragraph::new(vec![Line::from(vec![
                Span::styled("Status: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&status_message, Style::default().fg(Color::Green)),
                Span::raw("  |  "),
                Span::styled(
                    "[q]Quit [?]Help [Tab]Switch",
                    Style::default().fg(Color::DarkGray),
                ),
            ])])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(status, chunks[3]);
        })?;
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame) {
        let chunks = Layout::vertical([
            Constraint::Length(3), // Header
            Constraint::Length(3), // Tabs
            Constraint::Min(0),    // Content
            Constraint::Length(3), // Status
        ])
        .split(f.area());

        self.draw_header(f, chunks[0]);
        self.draw_tabs(f, chunks[1]);
        self.draw_content(f, chunks[2]);
        self.draw_status(f, chunks[3]);
    }

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let title = Paragraph::new(vec![Line::from(vec![
            Span::styled(
                "Obscell Wallet",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!("[{}]", self.config.network.name),
                Style::default().fg(Color::Yellow),
            ),
        ])])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(title, area);
    }

    fn draw_tabs(&self, f: &mut Frame, area: Rect) {
        let titles: Vec<Line> = Tab::all()
            .iter()
            .enumerate()
            .map(|(i, t)| {
                Line::from(vec![
                    Span::styled(
                        format!("[{}]", i + 1),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(t.title()),
                ])
            })
            .collect();

        let tabs = Tabs::new(titles)
            .block(Block::default().borders(Borders::ALL))
            .select(self.active_tab.index())
            .style(Style::default().fg(Color::White))
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );

        f.render_widget(tabs, area);
    }

    fn draw_content(&mut self, f: &mut Frame, area: Rect) {
        match self.active_tab {
            Tab::Accounts => {
                self.accounts_component.draw(f, area);
            }
            Tab::Send => {
                let block = Block::default()
                    .title("Send")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray));
                let paragraph = Paragraph::new("Send view - Coming soon...")
                    .block(block)
                    .style(Style::default().fg(Color::Gray));
                f.render_widget(paragraph, area);
            }
            Tab::Receive => {
                let block = Block::default()
                    .title("Receive")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray));
                let paragraph = Paragraph::new("Receive view - Coming soon...")
                    .block(block)
                    .style(Style::default().fg(Color::Gray));
                f.render_widget(paragraph, area);
            }
            Tab::Tokens => {
                let block = Block::default()
                    .title("Tokens")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray));
                let paragraph = Paragraph::new("Tokens view - Coming soon...")
                    .block(block)
                    .style(Style::default().fg(Color::Gray));
                f.render_widget(paragraph, area);
            }
            Tab::History => {
                let block = Block::default()
                    .title("History")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray));
                let paragraph = Paragraph::new("History view - Coming soon...")
                    .block(block)
                    .style(Style::default().fg(Color::Gray));
                f.render_widget(paragraph, area);
            }
        }
    }

    fn draw_status(&self, f: &mut Frame, area: Rect) {
        let status = Paragraph::new(vec![Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&self.status_message, Style::default().fg(Color::Green)),
            Span::raw("  |  "),
            Span::styled(
                "[q]Quit [?]Help [Tab]Switch",
                Style::default().fg(Color::DarkGray),
            ),
        ])])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(status, area);
    }
}
