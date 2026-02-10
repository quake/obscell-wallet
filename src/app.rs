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
    cli::Args,
    components::{
        Component, accounts::AccountsComponent, dev::DevComponent, history::HistoryComponent,
        receive::ReceiveComponent, send::SendComponent, settings::SettingsComponent,
        tokens::TokensComponent,
    },
    config::Config,
    domain::{
        account::AccountManager,
        cell::{TxRecord, aggregate_ct_balances_with_info},
        ct_info::{CtInfoData, MINTABLE},
        ct_mint::{
            CtInfoCellInput, FundingCell, GenesisParams, MintParams, build_genesis_transaction,
            build_mint_transaction, sign_genesis_transaction, sign_mint_transaction,
        },
        ct_tx_builder::CtTxBuilder,
        tx_builder::{StealthTxBuilder, parse_stealth_address},
    },
    infra::{devnet::DevNet, faucet::Faucet, scanner::Scanner, store::Store},
    tui::{Event, Frame, Tui},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Settings,
    Accounts,
    Send,
    Receive,
    Tokens,
    History,
    Dev,
}

impl Tab {
    pub fn all(dev_mode: bool) -> Vec<Tab> {
        let mut tabs = vec![
            Tab::Settings,
            Tab::Accounts,
            Tab::Send,
            Tab::Receive,
            Tab::Tokens,
            Tab::History,
        ];
        if dev_mode {
            tabs.push(Tab::Dev);
        }
        tabs
    }

    pub fn title(&self) -> Line<'static> {
        match self {
            Tab::Settings => Line::from(vec![
                Span::styled("S", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw("ettings"),
            ]),
            Tab::Accounts => Line::from(vec![
                Span::styled("A", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw("ccounts"),
            ]),
            Tab::Send => Line::from(vec![
                Span::styled("W", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw("ithdraw"),
            ]),
            Tab::Receive => Line::from(vec![
                Span::raw("Recei"),
                Span::styled("v", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw("e"),
            ]),
            Tab::Tokens => Line::from(vec![
                Span::raw("T"),
                Span::styled("o", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw("kens"),
            ]),
            Tab::History => Line::from(vec![
                Span::styled("H", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw("istory"),
            ]),
            Tab::Dev => Line::from(vec![
                Span::styled("D", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw("ev"),
            ]),
        }
    }

    pub fn index(&self, dev_mode: bool) -> usize {
        match self {
            Tab::Settings => 0,
            Tab::Accounts => 1,
            Tab::Send => 2,
            Tab::Receive => 3,
            Tab::Tokens => 4,
            Tab::History => 5,
            Tab::Dev if dev_mode => 6,
            Tab::Dev => 5, // Fallback if somehow Dev tab is accessed without dev_mode
        }
    }

    pub fn from_index(index: usize, dev_mode: bool) -> Tab {
        match index {
            0 => Tab::Settings,
            1 => Tab::Accounts,
            2 => Tab::Send,
            3 => Tab::Receive,
            4 => Tab::Tokens,
            5 => Tab::History,
            6 if dev_mode => Tab::Dev,
            _ => Tab::Settings,
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
    pub scanner: Scanner,
    pub account_manager: AccountManager,
    pub settings_component: SettingsComponent,
    pub accounts_component: AccountsComponent,
    pub receive_component: ReceiveComponent,
    pub send_component: SendComponent,
    pub history_component: HistoryComponent,
    pub tokens_component: TokensComponent,
    pub status_message: String,
    pub tip_block_number: Option<u64>,
    pub is_scanning: bool,
    pub last_auto_scan: Option<u64>,
    // Dev mode fields
    pub dev_mode: bool,
    pub dev_component: Option<DevComponent>,
    pub devnet: Option<DevNet>,
    pub faucet: Option<Faucet>,
    pub auto_mining_enabled: bool,
    pub auto_mining_interval: u64,
    pub indexer_synced: bool,
    pub checkpoint_block: Option<u64>,
}

impl App {
    pub fn new(args: &Args) -> Result<Self> {
        let (action_tx, action_rx) = mpsc::unbounded_channel();
        let config = Config::new(&args.network, args.rpc_url.as_deref());
        let store = Store::new(&config.network.name)?;
        let scanner = Scanner::new(config.clone(), store.clone());
        let account_manager = AccountManager::new(store.clone());
        let settings_component = SettingsComponent::new(action_tx.clone(), &config.network.name);
        let mut accounts_component = AccountsComponent::new(action_tx.clone());
        accounts_component.set_is_mainnet(config.network.name == "mainnet");
        let receive_component = ReceiveComponent::new(action_tx.clone());
        let send_component = SendComponent::new(action_tx.clone());
        let history_component = HistoryComponent::new();
        let tokens_component = TokensComponent::new(action_tx.clone());

        let tui = Tui::new()?
            .tick_rate(args.tick_rate)
            .frame_rate(args.frame_rate)
            .mouse(false)
            .paste(true);

        // Dev mode is enabled when network is "devnet"
        let dev_mode = config.network.name == "devnet";
        let (dev_component, devnet, faucet) = if dev_mode {
            let dev_component = DevComponent::new(action_tx.clone());
            let devnet = DevNet::with_defaults();
            // Use devnet miner key (from ckb genesis spec)
            // This is the well-known devnet miner private key
            let miner_key_bytes =
                hex::decode("d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc")
                    .expect("Invalid miner key hex");
            let miner_key =
                secp256k1::SecretKey::from_slice(&miner_key_bytes).expect("Invalid miner key");
            let miner_lock_args = Faucet::derive_lock_args(&miner_key);
            let faucet = Faucet::new(&config.network.rpc_url, miner_key, miner_lock_args);
            (Some(dev_component), Some(devnet), Some(faucet))
        } else {
            (None, None, None)
        };

        Ok(Self {
            should_quit: false,
            should_suspend: false,
            config,
            active_tab: Tab::Settings,
            last_tick_key_events: Vec::new(),
            action_tx,
            action_rx,
            tui,
            store,
            scanner,
            account_manager,
            settings_component,
            accounts_component,
            receive_component,
            send_component,
            history_component,
            tokens_component,
            status_message: "Ready".to_string(),
            tip_block_number: None,
            is_scanning: false,
            last_auto_scan: None,
            // Dev mode
            dev_mode,
            dev_component,
            devnet,
            faucet,
            auto_mining_enabled: false,
            auto_mining_interval: 3,
            indexer_synced: false,
            checkpoint_block: None,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        self.tui.enter()?;

        // Load accounts
        let accounts = self.account_manager.list_accounts()?;
        self.accounts_component.set_accounts(accounts.clone());

        // Set first account as active for receive, send, and dev components
        if let Some(first_account) = accounts.first() {
            self.receive_component
                .set_account(Some(first_account.clone()));
            self.send_component.set_account(Some(first_account.clone()));
            self.history_component
                .set_account(Some(first_account.clone()));
            self.tokens_component
                .set_account(Some(first_account.clone()));
            // Set dev component account if in dev mode
            if let Some(ref mut dev) = self.dev_component {
                dev.set_account(Some(first_account.clone()));
            }

            // Load transaction history for first account
            if let Ok(history) = self.store.get_tx_history(first_account.id) {
                self.history_component.set_transactions(history);
            }

            // Load CT cells and balances for first account
            if let Ok(ct_cells) = self.store.get_ct_cells(first_account.id) {
                let ct_info_cells = self
                    .store
                    .get_ct_info_cells(first_account.id)
                    .unwrap_or_default();
                let balances =
                    aggregate_ct_balances_with_info(&ct_cells, &ct_info_cells, &self.config);
                self.tokens_component.set_ct_cells(ct_cells);
                self.tokens_component.set_balances(balances);
            }
        }

        // Fetch tip block number
        match self.scanner.get_tip_block_number() {
            Ok(tip) => {
                self.tip_block_number = Some(tip);
                info!("Current tip block: {}", tip);
            }
            Err(e) => {
                info!("Failed to fetch tip block: {}", e);
            }
        }

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
            Event::Paste(text) => {
                self.handle_paste(&text)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        let is_editing = match self.active_tab {
            Tab::Send => self.send_component.is_editing,
            Tab::Tokens => self.tokens_component.is_editing(),
            Tab::Dev => self
                .dev_component
                .as_ref()
                .map(|d| d.is_editing)
                .unwrap_or(false),
            _ => false,
        };

        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.action_tx.send(Action::Quit)?;
            return Ok(());
        }

        if key.code == KeyCode::Char('v') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Ok(());
        }

        if is_editing {
            match self.active_tab {
                Tab::Send => {
                    self.send_component.handle_key_event(key)?;
                }
                Tab::Tokens => {
                    self.tokens_component.handle_key_event(key)?;
                }
                Tab::Dev => {
                    if let Some(ref mut dev_component) = self.dev_component {
                        dev_component.handle_key_event(key)?;
                    }
                }
                _ => {}
            }
            return Ok(());
        }

        match key.code {
            KeyCode::Char('q') if key.modifiers.is_empty() => {
                self.action_tx.send(Action::Quit)?;
            }
            KeyCode::Char('z') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.action_tx.send(Action::Suspend)?;
            }
            KeyCode::Char('?') if key.modifiers.is_empty() => {
                self.action_tx.send(Action::Help)?;
            }
            KeyCode::Char('r') if key.modifiers.is_empty() => {
                self.action_tx.send(Action::Rescan)?;
            }
            KeyCode::Char('s') if key.modifiers.is_empty() => {
                self.active_tab = Tab::Settings;
            }
            KeyCode::Char('a') if key.modifiers.is_empty() => {
                self.active_tab = Tab::Accounts;
            }
            KeyCode::Char('w') if key.modifiers.is_empty() => {
                self.active_tab = Tab::Send;
            }
            KeyCode::Char('v') if key.modifiers.is_empty() => {
                self.active_tab = Tab::Receive;
            }
            KeyCode::Char('o') if key.modifiers.is_empty() => {
                self.active_tab = Tab::Tokens;
            }
            KeyCode::Char('h') if key.modifiers.is_empty() => {
                self.active_tab = Tab::History;
            }
            KeyCode::Char('d') if key.modifiers.is_empty() && self.dev_mode => {
                self.active_tab = Tab::Dev;
            }
            KeyCode::Tab => {
                let tabs = Tab::all(self.dev_mode);
                let next_index = (self.active_tab.index(self.dev_mode) + 1) % tabs.len();
                self.active_tab = Tab::from_index(next_index, self.dev_mode);
            }
            KeyCode::BackTab => {
                let tabs = Tab::all(self.dev_mode);
                let prev_index = if self.active_tab.index(self.dev_mode) == 0 {
                    tabs.len() - 1
                } else {
                    self.active_tab.index(self.dev_mode) - 1
                };
                self.active_tab = Tab::from_index(prev_index, self.dev_mode);
            }
            _ => match self.active_tab {
                Tab::Settings => {
                    self.settings_component.handle_key_event(key)?;
                }
                Tab::Accounts => {
                    self.accounts_component.handle_key_event(key)?;
                }
                Tab::Send => {
                    self.send_component.handle_key_event(key)?;
                }
                Tab::Receive => {
                    self.receive_component.handle_key_event(key)?;
                }
                Tab::Tokens => {
                    self.tokens_component.handle_key_event(key)?;
                }
                Tab::History => {
                    self.history_component.handle_key_event(key)?;
                }
                Tab::Dev => {
                    if let Some(ref mut dev_component) = self.dev_component {
                        dev_component.handle_key_event(key)?;
                    }
                }
            },
        }
        Ok(())
    }

    fn handle_paste(&mut self, text: &str) -> Result<()> {
        match self.active_tab {
            Tab::Send => {
                self.send_component.paste(text);
            }
            Tab::Tokens => {
                self.tokens_component.paste(text);
            }
            Tab::Dev => {
                if let Some(ref mut dev_component) = self.dev_component {
                    dev_component.paste(text);
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle_action(&mut self, action: Action) -> Result<()> {
        debug!("Handling action: {:?}", action);
        match action {
            Action::Tick => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Auto-scan for new cells every 5 seconds (if not already scanning)
                let auto_scan_interval = 5u64;
                let should_auto_scan = !self.is_scanning
                    && self
                        .last_auto_scan
                        .map(|last| now >= last + auto_scan_interval)
                        .unwrap_or(true);

                if should_auto_scan {
                    self.is_scanning = true;
                    let accounts = self.account_manager.list_accounts()?;
                    if !accounts.is_empty() {
                        match self.scanner.incremental_scan(&accounts) {
                            Ok(scan_all_result) => {
                                let mut has_new = false;
                                for result in &scan_all_result.stealth_results {
                                    if !result.new_cells.is_empty() {
                                        has_new = true;
                                        if let Err(e) = self
                                            .account_manager
                                            .update_balance(result.account_id, result.total_capacity)
                                        {
                                            info!(
                                                "Failed to update balance for account {}: {}",
                                                result.account_id, e
                                            );
                                        }
                                    }
                                }

                                // Check for new CT or CT-info cells too
                                if scan_all_result.ct_results.iter().any(|r| !r.new_cells.is_empty())
                                    || scan_all_result.ct_info_results.iter().any(|r| !r.new_cells.is_empty())
                                {
                                    has_new = true;
                                }

                                if has_new {
                                    self.accounts_component
                                        .set_accounts(self.account_manager.list_accounts()?);

                                    if let Ok(tip) = self.scanner.get_tip_block_number() {
                                        self.tip_block_number = Some(tip);
                                    }
                                }
                            }
                            Err(e) => {
                                info!("Auto-scan failed: {}", e);
                            }
                        }
                    }
                    // Update timestamp after scan completes, so interval is measured
                    // from end of last scan, not start
                    self.last_auto_scan = Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    );
                    self.is_scanning = false;
                }

                // Handle auto-mining in dev mode
                if self.dev_mode && self.auto_mining_enabled {
                    static LAST_MINE_TIME: std::sync::atomic::AtomicU64 =
                        std::sync::atomic::AtomicU64::new(0);

                    let last = LAST_MINE_TIME.load(std::sync::atomic::Ordering::Relaxed);

                    if now >= last + self.auto_mining_interval {
                        LAST_MINE_TIME.store(now, std::sync::atomic::Ordering::Relaxed);
                        if let Some(ref devnet) = self.devnet
                            && let Ok(hash) = devnet.generate_block()
                        {
                            self.status_message = format!(
                                "Auto-mined block: {}...{}",
                                &hex::encode(&hash.0[..4]),
                                &hex::encode(&hash.0[28..])
                            );
                            if let Ok(tip) = self.scanner.get_tip_block_number() {
                                self.tip_block_number = Some(tip);
                            }
                        }
                    }
                }

                // Periodically refresh indexer sync status in dev mode
                if self.dev_mode
                    && let Some(ref devnet) = self.devnet
                {
                    self.indexer_synced = devnet.is_indexer_synced().unwrap_or(false);
                }
            }
            Action::Quit => {
                self.should_quit = true;
            }
            Action::Suspend => {
                self.should_suspend = true;
            }
            Action::CreateAccount => {
                let account = self.account_manager.create_account(format!(
                    "Account {}",
                    self.account_manager.list_accounts()?.len() + 1
                ))?;
                self.accounts_component
                    .set_accounts(self.account_manager.list_accounts()?);
                self.status_message = format!("Created account: {}", account.name);
            }
            Action::SelectAccount(index) => {
                self.account_manager.set_active_account(index)?;
                // Update receive, send, history, tokens, and dev components with selected account
                let accounts = self.account_manager.list_accounts()?;
                if let Some(account) = accounts.get(index) {
                    self.receive_component.set_account(Some(account.clone()));
                    self.send_component.set_account(Some(account.clone()));
                    self.history_component.set_account(Some(account.clone()));
                    self.tokens_component.set_account(Some(account.clone()));
                    // Update dev component if in dev mode
                    if let Some(ref mut dev) = self.dev_component {
                        dev.set_account(Some(account.clone()));
                    }

                    // Load transaction history for this account
                    if let Ok(history) = self.store.get_tx_history(account.id) {
                        self.history_component.set_transactions(history);
                    }

                    // Load CT cells and balances for this account
                    if let Ok(ct_cells) = self.store.get_ct_cells(account.id) {
                        let ct_info_cells =
                            self.store.get_ct_info_cells(account.id).unwrap_or_default();
                        let balances =
                            aggregate_ct_balances_with_info(&ct_cells, &ct_info_cells, &self.config);
                        self.tokens_component.set_ct_cells(ct_cells);
                        self.tokens_component.set_balances(balances);
                    }
                }
                self.status_message = format!("Selected account {}", index);
            }
            Action::Rescan => {
                self.status_message = "Rescanning...".to_string();
                self.is_scanning = true;

                // Get accounts to scan
                let accounts = self.account_manager.list_accounts()?;
                if accounts.is_empty() {
                    self.status_message = "No accounts to scan".to_string();
                    self.is_scanning = false;
                } else {
                    // Incremental scan: stealth + CT + CT-info in one pass
                    match self.scanner.incremental_scan(&accounts) {
                        Ok(scan_all_result) => {
                            let mut total_cells = 0usize;
                            let mut total_capacity = 0u64;
                            let mut new_receives = 0usize;

                            for result in &scan_all_result.stealth_results {
                                total_cells += result.cells.len();
                                total_capacity += result.total_capacity;
                                new_receives += result.new_cells.len();

                                // Update account balance
                                if let Err(e) = self
                                    .account_manager
                                    .update_balance(result.account_id, result.total_capacity)
                                {
                                    info!(
                                        "Failed to update balance for account {}: {}",
                                        result.account_id, e
                                    );
                                }
                            }

                            // Log CT-info results
                            let new_ct_info: usize = scan_all_result
                                .ct_info_results
                                .iter()
                                .map(|r| r.new_cells.len())
                                .sum();
                            if new_ct_info > 0 {
                                let total_ct_info: usize = scan_all_result
                                    .ct_info_results
                                    .iter()
                                    .map(|r| r.cells.len())
                                    .sum();
                                info!(
                                    "CT-info scan: {} cells found (+{} new)",
                                    total_ct_info, new_ct_info
                                );
                            }

                            // Refresh accounts display
                            self.accounts_component
                                .set_accounts(self.account_manager.list_accounts()?);

                            // Refresh history for current account
                            if let Some(account) = &self.history_component.account
                                && let Ok(history) = self.store.get_tx_history(account.id)
                            {
                                self.history_component.set_transactions(history);
                            }

                            let ckb_amount = total_capacity as f64 / 100_000_000.0;
                            if new_receives > 0 {
                                self.status_message = format!(
                                    "Scan complete: {} cells, {:.8} CKB (+{} new)",
                                    total_cells, ckb_amount, new_receives
                                );
                            } else {
                                self.status_message = format!(
                                    "Scan complete: {} cells, {:.8} CKB",
                                    total_cells, ckb_amount
                                );
                            }
                        }
                        Err(e) => {
                            self.status_message = format!("Scan failed: {}", e);
                        }
                    }

                    self.is_scanning = false;
                }
            }
            Action::FullRescan => {
                // Full rescan: clear all cells and scan from beginning
                self.status_message = "Full rescan: scanning from block 0...".to_string();
                self.is_scanning = true;

                let accounts = self.account_manager.list_accounts()?;
                if accounts.is_empty() {
                    self.status_message = "No accounts to scan".to_string();
                    self.is_scanning = false;
                } else {
                    // Full scan: clears stored cells internally, starts from None cursor
                    match self.scanner.full_scan_all(&accounts) {
                        Ok(scan_all_result) => {
                            let mut total_cells = 0usize;
                            let mut total_capacity = 0u64;

                            for result in &scan_all_result.stealth_results {
                                total_cells += result.cells.len();
                                total_capacity += result.total_capacity;

                                // Update account balance
                                if let Err(e) = self
                                    .account_manager
                                    .update_balance(result.account_id, result.total_capacity)
                                {
                                    info!(
                                        "Failed to update balance for account {}: {}",
                                        result.account_id, e
                                    );
                                }
                            }

                            // Refresh accounts display
                            self.accounts_component
                                .set_accounts(self.account_manager.list_accounts()?);

                            // Refresh history for current account
                            if let Some(account) = &self.history_component.account
                                && let Ok(history) = self.store.get_tx_history(account.id)
                            {
                                self.history_component.set_transactions(history);
                            }

                            let ckb_amount = total_capacity as f64 / 100_000_000.0;
                            self.status_message = format!(
                                "Full rescan complete: {} cells, {:.8} CKB",
                                total_cells, ckb_amount
                            );
                        }
                        Err(e) => {
                            self.status_message = format!("Full rescan failed: {}", e);
                        }
                    }

                    self.is_scanning = false;
                }
            }
            Action::SendTransaction => {
                // Get send parameters
                let recipient = self.send_component.recipient.clone();
                let amount = self.send_component.parse_amount();

                if let (Some(ref account), Some(amount_shannon)) =
                    (self.send_component.account.clone(), amount)
                {
                    // Parse the recipient stealth address
                    let stealth_addr = match parse_stealth_address(&recipient) {
                        Ok(addr) => addr,
                        Err(e) => {
                            self.send_component.error_message =
                                Some(format!("Invalid recipient: {}", e));
                            self.status_message = "Send failed: invalid address".to_string();
                            return Ok(());
                        }
                    };

                    // Get available cells for this account
                    let available_cells = match self.store.get_stealth_cells(account.id) {
                        Ok(cells) => cells,
                        Err(e) => {
                            self.send_component.error_message =
                                Some(format!("Failed to get cells: {}", e));
                            self.status_message = "Send failed: storage error".to_string();
                            return Ok(());
                        }
                    };

                    if available_cells.is_empty() {
                        self.send_component.error_message =
                            Some("No available cells. Try rescanning first.".to_string());
                        self.status_message = "Send failed: no cells".to_string();
                        return Ok(());
                    }

                    // Build the transaction
                    let builder = StealthTxBuilder::new(self.config.clone());
                    let builder = match builder
                        .add_output(stealth_addr, amount_shannon)
                        .select_inputs(&available_cells, amount_shannon)
                    {
                        Ok(b) => b,
                        Err(e) => {
                            self.send_component.error_message =
                                Some(format!("Input selection failed: {}", e));
                            self.status_message = "Send failed: insufficient funds".to_string();
                            return Ok(());
                        }
                    };

                    // Get the selected input cells for signing
                    let input_cells = builder.inputs.clone();

                    let built_tx = match builder.build(account) {
                        Ok(tx) => tx,
                        Err(e) => {
                            self.send_component.error_message =
                                Some(format!("Build failed: {}", e));
                            self.status_message = "Send failed: build error".to_string();
                            return Ok(());
                        }
                    };

                    // Sign the transaction
                    let signed_tx =
                        match StealthTxBuilder::sign(built_tx.clone(), account, &input_cells) {
                            Ok(tx) => tx,
                            Err(e) => {
                                self.send_component.error_message =
                                    Some(format!("Signing failed: {}", e));
                                self.status_message = "Send failed: signing error".to_string();
                                return Ok(());
                            }
                        };

                    // Submit the transaction
                    match self.scanner.rpc().send_transaction(signed_tx) {
                        Ok(tx_hash) => {
                            let amount_ckb = amount_shannon as f64 / 100_000_000.0;
                            self.send_component.success_message = Some(format!(
                                "Transaction sent! Hash: {}...{}",
                                &hex::encode(&tx_hash.0[..4]),
                                &hex::encode(&tx_hash.0[28..])
                            ));
                            self.status_message = format!("Sent {:.8} CKB", amount_ckb);

                            // Save transaction record to history
                            let tx_record = TxRecord::stealth_send(
                                tx_hash.0,
                                recipient.clone(),
                                amount_shannon,
                            );
                            if let Err(e) = self.store.save_tx_record(account.id, &tx_record) {
                                info!("Failed to save transaction record: {}", e);
                            }

                            // Refresh history display
                            if let Ok(history) = self.store.get_tx_history(account.id) {
                                self.history_component.set_transactions(history);
                            }

                            // Remove spent cells from store
                            let spent_out_points: Vec<_> =
                                input_cells.iter().map(|c| c.out_point.clone()).collect();
                            if let Err(e) =
                                self.store.remove_spent_cells(account.id, &spent_out_points)
                            {
                                info!("Failed to remove spent cells: {}", e);
                            }

                            // Clear send form
                            self.send_component.clear();
                        }
                        Err(e) => {
                            self.send_component.error_message =
                                Some(format!("Submission failed: {}", e));
                            self.status_message = "Send failed: RPC error".to_string();
                        }
                    }
                } else {
                    self.send_component.error_message =
                        Some("No account selected or invalid amount".to_string());
                }
            }
            Action::SelectToken(index) => {
                // Update selected token index in tokens component
                self.tokens_component.selected_index = index;
                self.status_message = format!("Selected token {}", index);
            }
            Action::TransferToken => {
                // Get transfer parameters from tokens component
                let recipient = self.tokens_component.transfer_recipient.clone();
                let amount = self.tokens_component.parse_transfer_amount();

                // Get the selected token
                let selected_balance = self.tokens_component.selected_balance().cloned();

                if let (Some(ref account), Some(amount_value), Some(token_balance)) = (
                    self.tokens_component.account.clone(),
                    amount,
                    selected_balance,
                ) {
                    // Validate amount against balance
                    if amount_value > token_balance.total_amount {
                        self.tokens_component.error_message = Some(format!(
                            "Insufficient balance: have {}, need {}",
                            token_balance.total_amount, amount_value
                        ));
                        self.status_message =
                            "CT transfer failed: insufficient balance".to_string();
                        return Ok(());
                    }

                    // Parse the recipient stealth address
                    let stealth_addr = match parse_stealth_address(&recipient) {
                        Ok(addr) => addr,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Invalid recipient: {}", e));
                            self.status_message = "CT transfer failed: invalid address".to_string();
                            return Ok(());
                        }
                    };

                    // Get available CT cells for this account
                    let available_ct_cells = match self.store.get_ct_cells(account.id) {
                        Ok(cells) => cells,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Failed to get CT cells: {}", e));
                            self.status_message = "CT transfer failed: storage error".to_string();
                            return Ok(());
                        }
                    };

                    if available_ct_cells.is_empty() {
                        self.tokens_component.error_message =
                            Some("No available CT cells. Try rescanning first.".to_string());
                        self.status_message = "CT transfer failed: no cells".to_string();
                        return Ok(());
                    }

                    // Build the CT transaction
                    let builder =
                        CtTxBuilder::new(self.config.clone(), token_balance.type_script_args.clone());
                    let builder = match builder
                        .add_output(stealth_addr, amount_value)
                        .select_inputs(&available_ct_cells, amount_value)
                    {
                        Ok(b) => b,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Input selection failed: {}", e));
                            self.status_message =
                                "CT transfer failed: insufficient funds".to_string();
                            return Ok(());
                        }
                    };

                    // Get the selected input cells for signing
                    let input_cells = builder.inputs.clone();

                    let built_tx = match builder.build(account) {
                        Ok(tx) => tx,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Build failed: {}", e));
                            self.status_message = "CT transfer failed: build error".to_string();
                            return Ok(());
                        }
                    };

                    // Sign the transaction
                    // Note: No funding cell for now - transfers need to have sufficient CT input cells
                    let signed_tx =
                        match CtTxBuilder::sign(built_tx.clone(), account, &input_cells, None) {
                            Ok(tx) => tx,
                            Err(e) => {
                                self.tokens_component.error_message =
                                    Some(format!("Signing failed: {}", e));
                                self.status_message =
                                    "CT transfer failed: signing error".to_string();
                                return Ok(());
                            }
                        };

                    // Submit the transaction
                    match self.scanner.rpc().send_transaction(signed_tx) {
                        Ok(tx_hash) => {
                            self.tokens_component.success_message = Some(format!(
                                "CT Transfer sent! Hash: {}...{}",
                                &hex::encode(&tx_hash.0[..4]),
                                &hex::encode(&tx_hash.0[28..])
                            ));
                            self.status_message = format!("Transferred {} CT tokens", amount_value);

                            // Save transaction record to history
                            let tx_record = TxRecord::ct_transfer(
                                tx_hash.0,
                                token_balance.token_id,
                                amount_value,
                            );
                            if let Err(e) = self.store.save_tx_record(account.id, &tx_record) {
                                info!("Failed to save CT transaction record: {}", e);
                            }

                            // Refresh history display
                            if let Ok(history) = self.store.get_tx_history(account.id) {
                                self.history_component.set_transactions(history);
                            }

                            // Remove spent CT cells from store
                            let spent_out_points: Vec<_> =
                                input_cells.iter().map(|c| c.out_point.clone()).collect();
                            if let Err(e) = self
                                .store
                                .remove_spent_ct_cells(account.id, &spent_out_points)
                            {
                                info!("Failed to remove spent CT cells: {}", e);
                            }

                            // Refresh CT balances
                            if let Ok(ct_cells) = self.store.get_ct_cells(account.id) {
                                let ct_info_cells =
                                    self.store.get_ct_info_cells(account.id).unwrap_or_default();
                                let balances =
                                    aggregate_ct_balances_with_info(&ct_cells, &ct_info_cells, &self.config);
                                self.tokens_component.set_balances(balances);
                                self.tokens_component.set_ct_cells(ct_cells);
                            }

                            // Clear transfer form
                            self.tokens_component.clear_transfer();
                        }
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Submission failed: {}", e));
                            self.status_message = "CT transfer failed: RPC error".to_string();
                        }
                    }
                } else {
                    self.tokens_component.error_message = Some(
                        "No account selected, invalid amount, or no token selected".to_string(),
                    );
                    self.status_message = "CT transfer failed: missing data".to_string();
                }
            }
            Action::MintToken => {
                // Get mint parameters from tokens component
                let recipient = self.tokens_component.mint_recipient.clone();
                let amount = self.tokens_component.parse_mint_amount();

                // Get the selected token for minting
                let selected_balance = self.tokens_component.selected_balance().cloned();

                if let (Some(ref account), Some(amount_value), Some(token_balance)) = (
                    self.tokens_component.account.clone(),
                    amount,
                    selected_balance,
                ) {
                    // Parse the recipient stealth address
                    let stealth_addr = match parse_stealth_address(&recipient) {
                        Ok(addr) => addr,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Invalid recipient: {}", e));
                            self.status_message = "CT mint failed: invalid address".to_string();
                            return Ok(());
                        }
                    };

                    // Get the ct-info cell for this token from storage
                    let ct_info_cell = match self
                        .store
                        .get_ct_info_by_token_id(account.id, &token_balance.token_id)
                    {
                        Ok(Some(cell)) => cell,
                        Ok(None) => {
                            self.tokens_component.error_message = Some(
                                "No ct-info cell found for this token. You may not be the issuer."
                                    .to_string(),
                            );
                            self.status_message = "CT mint failed: no ct-info cell".to_string();
                            return Ok(());
                        }
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Failed to get ct-info cell: {}", e));
                            self.status_message = "CT mint failed: storage error".to_string();
                            return Ok(());
                        }
                    };

                    // Convert CtInfoCell to CtInfoCellInput for the mint builder
                    let ct_info_data = CtInfoData::new(
                        ct_info_cell.total_supply,
                        ct_info_cell.supply_cap,
                        ct_info_cell.flags,
                    );

                    let ct_info_input = CtInfoCellInput {
                        out_point: ct_info_cell.out_point.clone(),
                        lock_script_args: ct_info_cell.lock_script_args.clone(),
                        data: ct_info_data,
                        capacity: ct_info_cell.capacity,
                    };

                    // Find a suitable funding cell from the account's stealth cells
                    // Need at least 255 CKB (MIN_CT_CELL_CAPACITY) + fees
                    let min_funding_capacity = 256_00000000u64; // 256 CKB (255 for CT cell + 1 for fees)
                    let stealth_cells = match self.store.get_stealth_cells(account.id) {
                        Ok(cells) => cells,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Failed to get stealth cells: {}", e));
                            self.status_message = "CT mint failed: storage error".to_string();
                            return Ok(());
                        }
                    };

                    let funding_cell = stealth_cells.iter().find(|c| c.capacity >= min_funding_capacity);

                    let funding_cell = match funding_cell {
                        Some(cell) => cell,
                        None => {
                            self.tokens_component.error_message = Some(format!(
                                "No cell with at least {} CKB available for minting. Receive CKB first.",
                                min_funding_capacity / 100_000_000
                            ));
                            self.status_message = "CT mint failed: insufficient funds".to_string();
                            return Ok(());
                        }
                    };

                    // Build funding cell input
                    let funding_input = FundingCell {
                        out_point: funding_cell.out_point.clone(),
                        capacity: funding_cell.capacity,
                        lock_script_args: funding_cell.stealth_script_args.clone(),
                    };

                    let mint_params = MintParams {
                        ct_info_cell: ct_info_input,
                        token_id: token_balance.token_id,
                        mint_amount: amount_value,
                        recipient_stealth_address: stealth_addr.clone(),
                        funding_cell: funding_input.clone(),
                    };

                    // Build the mint transaction
                    let built_tx = match build_mint_transaction(&self.config, mint_params) {
                        Ok(tx) => tx,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Mint build failed: {}", e));
                            self.status_message = "CT mint failed: build error".to_string();
                            return Ok(());
                        }
                    };

                    // Sign the transaction (ct-info cell uses stealth-lock, requires secp256k1 signature)
                    let signed_tx = match sign_mint_transaction(
                        built_tx,
                        account,
                        &ct_info_cell.lock_script_args,
                        &funding_input.lock_script_args,
                    ) {
                        Ok(tx) => tx,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Mint signing failed: {}", e));
                            self.status_message = "CT mint failed: signing error".to_string();
                            return Ok(());
                        }
                    };

                    // Submit the signed transaction
                    match self.scanner.rpc().send_transaction(signed_tx) {
                        Ok(tx_hash) => {
                            self.tokens_component.success_message = Some(format!(
                                "CT Mint sent! Hash: {}...{}",
                                &hex::encode(&tx_hash.0[..4]),
                                &hex::encode(&tx_hash.0[28..])
                            ));
                            self.status_message = format!("Minted {} CT tokens", amount_value);

                            // Save transaction record to history
                            let tx_record = TxRecord::ct_mint(
                                tx_hash.0,
                                token_balance.token_id,
                                amount_value,
                            );
                            if let Err(e) = self.store.save_tx_record(account.id, &tx_record) {
                                info!("Failed to save CT mint record: {}", e);
                            }

                            // Refresh history display
                            if let Ok(history) = self.store.get_tx_history(account.id) {
                                self.history_component.set_transactions(history);
                            }

                            // Clear mint form
                            self.tokens_component.clear_mint();
                        }
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Mint submission failed: {}", e));
                            self.status_message = "CT mint failed: RPC error".to_string();
                        }
                    }
                } else {
                    self.tokens_component.error_message = Some(
                        "No account selected, invalid amount, or no token selected".to_string(),
                    );
                    self.status_message = "CT mint failed: missing data".to_string();
                }
            }
            Action::CreateToken => {
                // Genesis: Create a new CT token
                if let Some(ref account) = self.tokens_component.account.clone() {
                    // Get supply cap from genesis form
                    let supply_cap = self
                        .tokens_component
                        .parse_genesis_supply_cap()
                        .unwrap_or(0);

                    // Get account's stealth address for issuer ownership
                    let stealth_address_hex = account.stealth_address();
                    let stealth_address = match hex::decode(&stealth_address_hex) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Invalid stealth address: {}", e));
                            self.status_message = "Genesis failed: invalid address".to_string();
                            return Ok(());
                        }
                    };

                    // Find a suitable funding cell from the account's stealth cells
                    let stealth_cells = match self.store.get_stealth_cells(account.id) {
                        Ok(cells) => cells,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Failed to get stealth cells: {}", e));
                            self.status_message = "Genesis failed: storage error".to_string();
                            return Ok(());
                        }
                    };

                    // Need at least 230 CKB for ct-info cell
                    let min_capacity = 230_00000000u64;
                    let funding_cell = stealth_cells.iter().find(|c| c.capacity >= min_capacity);

                    let funding_cell = match funding_cell {
                        Some(cell) => cell,
                        None => {
                            self.tokens_component.error_message = Some(format!(
                                "No cell with at least {} CKB available. Receive CKB first.",
                                min_capacity / 100_000_000
                            ));
                            self.status_message = "Genesis failed: insufficient funds".to_string();
                            return Ok(());
                        }
                    };

                    // Build genesis params
                    let genesis_params = GenesisParams {
                        supply_cap,
                        flags: MINTABLE,
                        issuer_stealth_address: stealth_address,
                    };

                    // Build funding cell input
                    let funding_input = FundingCell {
                        out_point: funding_cell.out_point.clone(),
                        capacity: funding_cell.capacity,
                        lock_script_args: funding_cell.stealth_script_args.clone(),
                    };

                    // Build the genesis transaction
                    let built_tx = match build_genesis_transaction(
                        &self.config,
                        genesis_params,
                        funding_input,
                    ) {
                        Ok(tx) => tx,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Genesis build failed: {}", e));
                            self.status_message = "Genesis failed: build error".to_string();
                            return Ok(());
                        }
                    };

                    // Remember the token ID and ct-info lock args for later use
                    let token_id = built_tx.token_id;

                    // Sign the transaction with the funding cell's stealth key
                    let signed_tx = match sign_genesis_transaction(
                        built_tx,
                        account,
                        &funding_cell.stealth_script_args,
                    ) {
                        Ok(tx) => tx,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Genesis signing failed: {}", e));
                            self.status_message = "Genesis failed: signing error".to_string();
                            return Ok(());
                        }
                    };

                    // Submit the transaction
                    match self.scanner.rpc().send_transaction(signed_tx) {
                        Ok(tx_hash) => {
                            self.tokens_component.success_message = Some(format!(
                                "Token created! Hash: {}...{}\nToken ID: {}...{}",
                                &hex::encode(&tx_hash.0[..4]),
                                &hex::encode(&tx_hash.0[28..]),
                                &hex::encode(&token_id[..4]),
                                &hex::encode(&token_id[28..])
                            ));
                            self.status_message = format!(
                                "Created new token {}...{}",
                                &hex::encode(&token_id[..4]),
                                &hex::encode(&token_id[28..])
                            );

                            // Save transaction record to history
                            let tx_record = TxRecord::ct_genesis(tx_hash.0, token_id);
                            if let Err(e) = self.store.save_tx_record(account.id, &tx_record) {
                                info!("Failed to save genesis record: {}", e);
                            }

                            // Refresh history display
                            if let Ok(history) = self.store.get_tx_history(account.id) {
                                self.history_component.set_transactions(history);
                            }

                            // Remove spent stealth cell from store
                            if let Err(e) = self.store.remove_spent_cells(
                                account.id,
                                std::slice::from_ref(&funding_cell.out_point),
                            ) {
                                info!("Failed to remove spent stealth cell: {}", e);
                            }

                            // Trigger a rescan to detect the new ct-info cell
                            // (The transaction needs to be confirmed first, so we inform user)
                            self.status_message
                                .push_str(" - Press 'r' to rescan after confirmation");

                            // Clear genesis form and return to list
                            self.tokens_component.clear_genesis();
                            self.tokens_component.mode =
                                crate::components::tokens::TokensMode::List;
                        }
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Genesis submission failed: {}", e));
                            self.status_message = "Genesis failed: RPC error".to_string();
                        }
                    }
                } else {
                    self.tokens_component.error_message = Some("No account selected".to_string());
                    self.status_message = "Genesis failed: no account".to_string();
                }
            }
            // Dev mode actions
            Action::TabDev if self.dev_mode => {
                self.active_tab = Tab::Dev;
            }
            Action::GenerateBlock if self.dev_mode => {
                if let Some(ref devnet) = self.devnet {
                    match devnet.generate_block() {
                        Ok(hash) => {
                            self.status_message = format!(
                                "Generated block: {}...{}",
                                &hex::encode(&hash.0[..4]),
                                &hex::encode(&hash.0[28..])
                            );
                            // Refresh tip block number
                            if let Ok(tip) = self.scanner.get_tip_block_number() {
                                self.tip_block_number = Some(tip);
                            }
                        }
                        Err(e) => {
                            self.status_message = format!("Block generation failed: {}", e);
                            if let Some(ref mut dev) = self.dev_component {
                                dev.error_message = Some(e.to_string());
                            }
                        }
                    }
                }
            }
            Action::GenerateBlocks(count) if self.dev_mode => {
                if let Some(ref devnet) = self.devnet {
                    match devnet.generate_blocks(count) {
                        Ok(()) => {
                            self.status_message = format!("Generated {} blocks", count);
                            if let Ok(tip) = self.scanner.get_tip_block_number() {
                                self.tip_block_number = Some(tip);
                            }
                        }
                        Err(e) => {
                            self.status_message = format!("Block generation failed: {}", e);
                            if let Some(ref mut dev) = self.dev_component {
                                dev.error_message = Some(e.to_string());
                            }
                        }
                    }
                }
            }
            Action::SaveCheckpoint if self.dev_mode => {
                if let Some(ref devnet) = self.devnet {
                    match devnet.save_current_as_checkpoint() {
                        Ok(tip) => {
                            self.checkpoint_block = Some(tip);
                            if let Some(ref mut dev) = self.dev_component {
                                dev.set_checkpoint(Some(tip));
                                dev.success_message =
                                    Some(format!("Checkpoint saved at block #{}", tip));
                            }
                            self.status_message = format!("Checkpoint saved at block #{}", tip);
                        }
                        Err(e) => {
                            self.status_message = format!("Failed to save checkpoint: {}", e);
                            if let Some(ref mut dev) = self.dev_component {
                                dev.error_message = Some(e.to_string());
                            }
                        }
                    }
                }
            }
            Action::ResetToCheckpoint if self.dev_mode => {
                if let Some(ref devnet) = self.devnet {
                    match devnet.reset_to_checkpoint() {
                        Ok(()) => {
                            if let Ok(tip) = self.scanner.get_tip_block_number() {
                                self.tip_block_number = Some(tip);
                                self.status_message =
                                    format!("Reset to checkpoint (now at block #{})", tip);
                            } else {
                                self.status_message = "Reset to checkpoint".to_string();
                            }
                            if let Some(ref mut dev) = self.dev_component {
                                dev.success_message = Some("Reset to checkpoint".to_string());
                            }
                        }
                        Err(e) => {
                            self.status_message = format!("Reset failed: {}", e);
                            if let Some(ref mut dev) = self.dev_component {
                                dev.error_message = Some(e.to_string());
                            }
                        }
                    }
                }
            }
            Action::ToggleAutoMining if self.dev_mode => {
                self.auto_mining_enabled = !self.auto_mining_enabled;
                if let Some(ref mut dev) = self.dev_component {
                    dev.auto_mining = self.auto_mining_enabled;
                }
                let status = if self.auto_mining_enabled {
                    "ON"
                } else {
                    "OFF"
                };
                self.status_message = format!("Auto-mining: {}", status);
            }
            Action::SetMiningInterval(interval) if self.dev_mode => {
                self.auto_mining_interval = interval.clamp(1, 10);
                if let Some(ref mut dev) = self.dev_component {
                    dev.mining_interval = self.auto_mining_interval;
                }
                self.status_message = format!("Mining interval: {}s", self.auto_mining_interval);
            }
            Action::SendFaucet if self.dev_mode => {
                // Get the faucet amount from dev component
                let amount = self
                    .dev_component
                    .as_ref()
                    .and_then(|d| d.parse_faucet_amount());
                let account = self.dev_component.as_ref().and_then(|d| d.account.clone());

                if let (Some(faucet), Some(amount), Some(account)) =
                    (&self.faucet, amount, account)
                {
                    // Generate a one-time stealth lock args from the account's public keys
                    // The stealth_address() returns view_pub || spend_pub (66 bytes meta address)
                    // But we need to generate a proper one-time address:
                    // ephemeral_pubkey (33B) || pubkey_hash (20B) = 53 bytes
                    let view_pub = account.view_public_key();
                    let spend_pub = account.spend_public_key();
                    let (eph_pub, stealth_pub) =
                        crate::domain::stealth::generate_ephemeral_key(&view_pub, &spend_pub);
                    let pubkey_hash = ckb_hash::blake2b_256(stealth_pub.serialize());
                    let stealth_lock_args =
                        [eph_pub.serialize().as_slice(), &pubkey_hash[0..20]].concat();

                    // Get stealth lock code hash from config and convert to H256
                    let code_hash_str = self
                        .config
                        .contracts
                        .stealth_lock_code_hash
                        .trim_start_matches("0x");
                    let code_hash_bytes = match hex::decode(code_hash_str) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            self.status_message = format!("Invalid code hash: {}", e);
                            if let Some(ref mut dev) = self.dev_component {
                                dev.error_message = Some(e.to_string());
                            }
                            return Ok(());
                        }
                    };
                    let stealth_lock_code_hash =
                        match ckb_types::H256::from_slice(&code_hash_bytes) {
                            Ok(h) => h,
                            Err(e) => {
                                self.status_message = format!("Invalid code hash: {}", e);
                                if let Some(ref mut dev) = self.dev_component {
                                    dev.error_message = Some(format!("{:?}", e));
                                }
                                return Ok(());
                            }
                        };

                    match faucet.transfer_to_stealth(
                        &stealth_lock_args,
                        &stealth_lock_code_hash,
                        amount,
                    ) {
                        Ok(tx_hash) => {
                            let ckb_amount = amount as f64 / 100_000_000.0;
                            self.status_message = format!("Faucet sent {:.8} CKB", ckb_amount);
                            if let Some(ref mut dev) = self.dev_component {
                                dev.success_message = Some(format!(
                                    "Sent {:.8} CKB! Tx: {}...{}",
                                    ckb_amount,
                                    &hex::encode(&tx_hash.0[..4]),
                                    &hex::encode(&tx_hash.0[28..])
                                ));
                            }
                        }
                        Err(e) => {
                            self.status_message = format!("Faucet failed: {}", e);
                            if let Some(ref mut dev) = self.dev_component {
                                dev.error_message = Some(e.to_string());
                            }
                        }
                    }
                } else {
                    self.status_message = "Faucet failed: missing account or amount".to_string();
                    if let Some(ref mut dev) = self.dev_component {
                        dev.error_message = Some("Missing account or amount".to_string());
                    }
                }
            }
            Action::RefreshDevStatus if self.dev_mode => {
                // Refresh tip block and indexer status
                if let Ok(tip) = self.scanner.get_tip_block_number() {
                    self.tip_block_number = Some(tip);
                }
                if let Some(ref devnet) = self.devnet {
                    self.indexer_synced = devnet.is_indexer_synced().unwrap_or(false);
                }
                // Refresh miner balance
                if let Some(ref faucet) = self.faucet
                    && let Ok(balance) = faucet.get_miner_balance()
                    && let Some(ref mut dev) = self.dev_component
                {
                    dev.set_miner_balance(Some(balance));
                }
                self.status_message = "Dev status refreshed".to_string();
            }
            Action::SwitchNetwork(ref network) => {
                // Switch to a different network
                let new_config = Config::from_network(network);
                let new_dev_mode = new_config.network.name == "devnet";

                // Rebuild store and account manager for the new network's data directory
                let new_store = Store::new(&new_config.network.name)?;
                let new_account_manager = AccountManager::new(new_store.clone());

                // Update core state
                self.config = new_config.clone();
                self.store = new_store;
                self.account_manager = new_account_manager;
                self.scanner = Scanner::new(self.config.clone(), self.store.clone());
                self.is_scanning = false;
                self.last_auto_scan = None;

                // Reload accounts from the new store
                let accounts = self.account_manager.list_accounts()?;
                self.accounts_component.set_accounts(accounts.clone());
                self.settings_component.set_network(&self.config.network.name);
                self.accounts_component.set_is_mainnet(self.config.network.name == "mainnet");

                // Reset UI components with the first account (if any)
                if let Some(first_account) = accounts.first() {
                    self.receive_component
                        .set_account(Some(first_account.clone()));
                    self.send_component.set_account(Some(first_account.clone()));
                    self.history_component
                        .set_account(Some(first_account.clone()));
                    self.tokens_component
                        .set_account(Some(first_account.clone()));

                    if let Ok(history) = self.store.get_tx_history(first_account.id) {
                        self.history_component.set_transactions(history);
                    }

                    if let Ok(ct_cells) = self.store.get_ct_cells(first_account.id) {
                        let ct_info_cells = self
                            .store
                            .get_ct_info_cells(first_account.id)
                            .unwrap_or_default();
                        let balances = aggregate_ct_balances_with_info(
                            &ct_cells,
                            &ct_info_cells,
                            &self.config,
                        );
                        self.tokens_component.set_ct_cells(ct_cells);
                        self.tokens_component.set_balances(balances);
                    }
                } else {
                    self.receive_component.set_account(None);
                    self.send_component.set_account(None);
                    self.history_component.set_account(None);
                    self.tokens_component.set_account(None);
                    self.history_component.set_transactions(Vec::new());
                    self.tokens_component.set_ct_cells(Vec::new());
                    self.tokens_component.set_balances(Vec::new());
                }

                // Handle dev mode transition
                if new_dev_mode && !self.dev_mode {
                    // Entering dev mode - create dev components
                    let dev_component = DevComponent::new(self.action_tx.clone());
                    let devnet = DevNet::with_defaults();
                    let miner_key_bytes =
                        hex::decode("d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc")
                            .expect("Invalid miner key hex");
                    let miner_key =
                        secp256k1::SecretKey::from_slice(&miner_key_bytes).expect("Invalid miner key");
                    let miner_lock_args = Faucet::derive_lock_args(&miner_key);
                    let faucet = Faucet::new(&self.config.network.rpc_url, miner_key, miner_lock_args);

                    self.dev_component = Some(dev_component);
                    self.devnet = Some(devnet);
                    self.faucet = Some(faucet);

                    // Set account for dev component
                    if let Some(account) = self.accounts_component.accounts.first()
                        && let Some(ref mut dev) = self.dev_component
                    {
                        dev.set_account(Some(account.clone()));
                    }
                } else if !new_dev_mode && self.dev_mode {
                    // Leaving dev mode - cleanup dev components
                    self.dev_component = None;
                    self.devnet = None;
                    self.faucet = None;
                    self.auto_mining_enabled = false;
                    self.indexer_synced = false;
                    self.checkpoint_block = None;

                    // If currently on Dev tab, switch to Settings
                    if self.active_tab == Tab::Dev {
                        self.active_tab = Tab::Settings;
                    }
                }

                self.dev_mode = new_dev_mode;

                // Refresh tip block for new network
                match self.scanner.get_tip_block_number() {
                    Ok(tip) => {
                        self.tip_block_number = Some(tip);
                    }
                    Err(_) => {
                        self.tip_block_number = None;
                    }
                }

                self.status_message = format!("Switched to {}", self.config.network.name);
            }
            _ => {}
        }
        Ok(())
    }

    fn draw_ui(&mut self) -> Result<()> {
        // Collect all data needed for drawing before borrowing terminal
        let config_network_name = self.config.network.name.clone();
        let is_mainnet = config_network_name == "mainnet";
        let active_tab = self.active_tab;
        let status_message = self.status_message.clone();
        let accounts = self.accounts_component.accounts.clone();
        let selected_index = self.accounts_component.selected_index;
        let tip_block_number = self.tip_block_number;
        let receive_account = self.receive_component.account.clone();
        let receive_one_time_address = self.receive_component.one_time_address.clone();
        let receive_script_args = self.receive_component.script_args.clone();
        let send_account = self.send_component.account.clone();
        let send_recipient = self.send_component.recipient.clone();
        let send_amount = self.send_component.amount.clone();
        let send_focused_field = self.send_component.focused_field;
        let send_is_editing = self.send_component.is_editing;
        let send_error_message = self.send_component.error_message.clone();
        let send_success_message = self.send_component.success_message.clone();
        // Settings component data
        let settings_current_network = self.settings_component.current_network.clone();
        let settings_selected_index = self.settings_component.selected_index;
        // Tokens component data
        let tokens_account = self.tokens_component.account.clone();
        let tokens_balances = self.tokens_component.balances.clone();
        let tokens_selected_index = self.tokens_component.selected_index;
        let tokens_mode = self.tokens_component.mode;
        let tokens_transfer_recipient = self.tokens_component.transfer_recipient.clone();
        let tokens_transfer_amount = self.tokens_component.transfer_amount.clone();
        let tokens_transfer_field = self.tokens_component.transfer_field;
        let tokens_mint_recipient = self.tokens_component.mint_recipient.clone();
        let tokens_mint_amount = self.tokens_component.mint_amount.clone();
        let tokens_mint_field = self.tokens_component.mint_field;
        let tokens_genesis_supply_cap = self.tokens_component.genesis_supply_cap.clone();
        let tokens_genesis_unlimited = self.tokens_component.genesis_unlimited;
        let tokens_genesis_field = self.tokens_component.genesis_field;
        let tokens_is_editing = self.tokens_component.is_editing;
        let tokens_error_message = self.tokens_component.error_message.clone();
        let tokens_success_message = self.tokens_component.success_message.clone();
        // Dev mode data
        let dev_mode = self.dev_mode;
        let indexer_synced = self.indexer_synced;
        let dev_account = self.dev_component.as_ref().and_then(|d| d.account.clone());
        let dev_checkpoint = self.dev_component.as_ref().and_then(|d| d.checkpoint);
        let dev_auto_mining = self.dev_component.as_ref().map(|d| d.auto_mining).unwrap_or(false);
        let dev_mining_interval = self.dev_component.as_ref().map(|d| d.mining_interval).unwrap_or(3);
        let dev_miner_balance = self.dev_component.as_ref().and_then(|d| d.miner_balance);
        let dev_faucet_amount = self.dev_component.as_ref().map(|d| d.faucet_amount.clone()).unwrap_or_default();
        let dev_is_editing = self.dev_component.as_ref().map(|d| d.is_editing).unwrap_or(false);
        let dev_error_message = self.dev_component.as_ref().and_then(|d| d.error_message.clone());
        let dev_success_message = self.dev_component.as_ref().and_then(|d| d.success_message.clone());

        self.tui.draw(|f| {
            let chunks = Layout::vertical([
                Constraint::Length(3), // Header
                Constraint::Length(3), // Tabs
                Constraint::Min(0),    // Content
                Constraint::Length(3), // Status
            ])
            .split(f.area());

            // Draw header with dev mode indicator
            let mut header_spans = vec![
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
            ];
            if dev_mode {
                header_spans.push(Span::raw("  "));
                header_spans.push(Span::styled(
                    "[DEV]",
                    Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
                ));
                // Show indexer sync status
                let sync_status = if indexer_synced { "Synced" } else { "Syncing..." };
                let sync_color = if indexer_synced { Color::Green } else { Color::Yellow };
                header_spans.push(Span::raw("  "));
                header_spans.push(Span::styled(
                    format!("Indexer: {}", sync_status),
                    Style::default().fg(sync_color),
                ));
            }
            let title = Paragraph::new(vec![Line::from(header_spans)])
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray)),
                );
            f.render_widget(title, chunks[0]);

            // Draw tabs
            let titles: Vec<Line> = Tab::all(dev_mode)
                .iter()
                .map(|t| t.title())
                .collect();

            let tabs = Tabs::new(titles)
                .block(Block::default().borders(Borders::ALL))
                .select(active_tab.index(dev_mode))
                .style(Style::default().fg(Color::White))
                .highlight_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                );
            f.render_widget(tabs, chunks[1]);

            // Draw content
            match active_tab {
                Tab::Settings => {
                    SettingsComponent::draw_static(
                        f,
                        chunks[2],
                        &settings_current_network,
                        settings_selected_index,
                    );
                }
                Tab::Accounts => {
                    AccountsComponent::draw_static(f, chunks[2], &accounts, selected_index, is_mainnet);
                }
                Tab::Send => {
                    SendComponent::draw_static(
                        f,
                        chunks[2],
                        send_account.as_ref(),
                        &send_recipient,
                        &send_amount,
                        send_focused_field,
                        send_is_editing,
                        send_error_message.as_deref(),
                        send_success_message.as_deref(),
                    );
                }
                Tab::Receive => {
                    ReceiveComponent::draw_static(
                        f,
                        chunks[2],
                        receive_account.as_ref(),
                        receive_one_time_address.as_deref(),
                        receive_script_args.as_deref(),
                    );
                }
                Tab::Tokens => {
                    TokensComponent::draw_static(
                        f,
                        chunks[2],
                        tokens_account.as_ref(),
                        &tokens_balances,
                        tokens_selected_index,
                        tokens_mode,
                        &tokens_transfer_recipient,
                        &tokens_transfer_amount,
                        tokens_transfer_field,
                        &tokens_mint_recipient,
                        &tokens_mint_amount,
                        tokens_mint_field,
                        &tokens_genesis_supply_cap,
                        tokens_genesis_unlimited,
                        tokens_genesis_field,
                        tokens_is_editing,
                        tokens_error_message.as_deref(),
                        tokens_success_message.as_deref(),
                    );
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
                Tab::Dev => {
                    DevComponent::draw_static(
                        f,
                        chunks[2],
                        dev_account.as_ref(),
                        dev_checkpoint,
                        dev_auto_mining,
                        dev_mining_interval,
                        dev_miner_balance,
                        &dev_faucet_amount,
                        dev_is_editing,
                        dev_error_message.as_deref(),
                        dev_success_message.as_deref(),
                    );
                }
            }

            // Draw status
            let tip_str = tip_block_number
                .map(|n| format!("Block: {}", n))
                .unwrap_or_else(|| "Block: -".to_string());
            let status = Paragraph::new(vec![Line::from(vec![
                Span::styled("Status: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&status_message, Style::default().fg(Color::Green)),
                Span::raw("  |  "),
                Span::styled(&tip_str, Style::default().fg(Color::Yellow)),
                Span::raw("  |  "),
                Span::styled(
                    "[r]Rescan [q]Quit [?]Help",
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
        let titles: Vec<Line> = Tab::all(self.dev_mode)
            .iter()
            .map(|t| t.title())
            .collect();

        let tabs = Tabs::new(titles)
            .block(Block::default().borders(Borders::ALL))
            .select(self.active_tab.index(self.dev_mode))
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
            Tab::Settings => {
                self.settings_component.draw(f, area);
            }
            Tab::Accounts => {
                self.accounts_component.draw(f, area);
            }
            Tab::Send => {
                let block = Block::default()
                    .title("Send")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray));
                let paragraph = Paragraph::new("Withdraw view - Coming soon...")
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
                self.history_component.draw(f, area);
            }
            Tab::Dev => {
                if let Some(ref mut dev) = self.dev_component {
                    dev.draw(f, area);
                }
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
