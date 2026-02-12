use color_eyre::eyre::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEventKind};
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
        Component,
        accounts::AccountsComponent,
        dev::DevComponent,
        history::HistoryComponent,
        receive::ReceiveComponent,
        send::{AddressType, SendComponent, SendMode},
        settings::SettingsComponent,
        settings::SettingsMode,
        tokens::TokensComponent,
        wallet_setup::{SetupMode, WalletSetupComponent},
    },
    config::Config,
    domain::{
        account::AccountManager,
        cell::aggregate_ct_balances_with_info,
        ct_info::{CtInfoData, MINTABLE},
        ct_mint::{
            CtInfoCellInput, FundingCell, GenesisParams, MintParams, build_genesis_transaction,
            build_mint_transaction, sign_genesis_transaction, sign_mint_transaction,
        },
        ct_tx_builder::CtTxBuilder,
        tx_builder::{StealthTxBuilder, parse_stealth_address},
        wallet::WalletMeta,
    },
    infra::{
        devnet::DevNet,
        faucet::Faucet,
        scanner::Scanner,
        store::{SELECTED_NETWORK_KEY, Store},
    },
    tui::{Event, Frame, Tui},
};

/// Application mode - whether we're in wallet setup or normal operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppMode {
    /// First-time setup or wallet needs to be created/restored
    WalletSetup,
    /// Normal tab-based operation
    Normal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Settings,
    Accounts,
    Tokens,
    Send,
    Receive,
    History,
    Dev,
}

impl Tab {
    pub fn all(dev_mode: bool) -> Vec<Tab> {
        let mut tabs = vec![
            Tab::Accounts,
            Tab::Tokens,
            Tab::Send,
            Tab::Receive,
            Tab::History,
            Tab::Settings,
        ];
        if dev_mode {
            tabs.push(Tab::Dev);
        }
        tabs
    }

    pub fn title(&self) -> Line<'static> {
        let underline = Style::default().add_modifier(Modifier::UNDERLINED);
        match self {
            Tab::Settings => Line::from(vec![
                Span::raw("Settin"),
                Span::styled("g", underline),
                Span::raw("s"),
            ]),
            Tab::Accounts => Line::from(vec![Span::styled("A", underline), Span::raw("ccounts")]),
            Tab::Tokens => Line::from(vec![Span::styled("T", underline), Span::raw("okens")]),
            Tab::Send => Line::from(vec![Span::styled("S", underline), Span::raw("end")]),
            Tab::Receive => Line::from(vec![Span::styled("R", underline), Span::raw("eceive")]),
            Tab::History => Line::from(vec![Span::styled("H", underline), Span::raw("istory")]),
            Tab::Dev => Line::from(vec![Span::styled("D", underline), Span::raw("ev")]),
        }
    }

    pub fn index(&self, dev_mode: bool) -> usize {
        match self {
            Tab::Accounts => 0,
            Tab::Tokens => 1,
            Tab::Send => 2,
            Tab::Receive => 3,
            Tab::History => 4,
            Tab::Settings => 5,
            Tab::Dev if dev_mode => 6,
            Tab::Dev => 5, // Fallback if somehow Dev tab is accessed without dev_mode
        }
    }

    pub fn from_index(index: usize, dev_mode: bool) -> Tab {
        match index {
            0 => Tab::Accounts,
            1 => Tab::Tokens,
            2 => Tab::Send,
            3 => Tab::Receive,
            4 => Tab::History,
            5 => Tab::Settings,
            6 if dev_mode => Tab::Dev,
            _ => Tab::Accounts,
        }
    }
}

pub struct App {
    pub should_quit: bool,
    pub should_suspend: bool,
    pub config: Config,
    pub mode: AppMode,
    pub active_tab: Tab,
    pub last_tick_key_events: Vec<KeyEvent>,
    pub action_tx: UnboundedSender<Action>,
    pub action_rx: UnboundedReceiver<Action>,
    pub tui: Tui,
    pub store: Store,
    pub scanner: Scanner,
    pub account_manager: AccountManager,
    pub wallet_meta: Option<WalletMeta>,
    pub wallet_setup_component: WalletSetupComponent,
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
    /// Saved tab bar area for mouse click detection.
    pub tab_area: Rect,
    // Dev mode fields
    pub dev_mode: bool,
    pub dev_component: Option<DevComponent>,
    pub devnet: Option<DevNet>,
    pub faucet: Option<Faucet>,
    pub auto_mining_enabled: bool,
    pub auto_mining_interval: u64,
    pub indexer_synced: bool,
    pub checkpoint_block: Option<u64>,
    // Background scan channel
    pub scan_update_rx:
        Option<tokio::sync::mpsc::UnboundedReceiver<crate::infra::scanner::ScanUpdate>>,
}

impl App {
    pub fn new(args: &Args) -> Result<Self> {
        let (action_tx, action_rx) = mpsc::unbounded_channel();

        // Determine network: CLI arg > saved preference > default "testnet"
        let network = if let Some(ref net) = args.network {
            net.clone()
        } else if let Ok(global_store) = Store::global() {
            global_store
                .load_metadata::<String>(SELECTED_NETWORK_KEY)
                .ok()
                .flatten()
                .unwrap_or_else(|| "testnet".to_string())
        } else {
            "testnet".to_string()
        };

        let config = Config::new(&network, args.rpc_url.as_deref());
        let store = Store::new(&config.network.name)?;
        let scanner = Scanner::new(config.clone(), store.clone());
        let account_manager = AccountManager::new(store.clone());
        let settings_component = SettingsComponent::new(action_tx.clone(), &config.network.name);
        let accounts_component = AccountsComponent::new(action_tx.clone());
        let mut receive_component = ReceiveComponent::new(action_tx.clone());
        receive_component.set_config(config.clone());
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

        // Load existing wallet meta or initialize as None
        let wallet_meta = store.load_wallet_meta().ok().flatten();

        // Determine initial mode based on whether wallet exists
        let initial_mode = if wallet_meta.is_some() {
            AppMode::Normal
        } else {
            AppMode::WalletSetup
        };

        // Create wallet setup component
        let wallet_setup_component = WalletSetupComponent::new(action_tx.clone());

        Ok(Self {
            should_quit: false,
            should_suspend: false,
            config,
            mode: initial_mode,
            active_tab: Tab::Accounts,
            last_tick_key_events: Vec::new(),
            action_tx,
            action_rx,
            tui,
            store,
            scanner,
            account_manager,
            wallet_meta,
            wallet_setup_component,
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
            tab_area: Rect::default(),
            // Dev mode
            dev_mode,
            dev_component,
            devnet,
            faucet,
            auto_mining_enabled: false,
            auto_mining_interval: 3,
            indexer_synced: false,
            checkpoint_block: None,
            // Background scan
            scan_update_rx: None,
        })
    }

    /// Switch to a new tab and refresh data as needed.
    /// When switching to History tab, loads history for the currently selected account.
    fn switch_tab(&mut self, new_tab: Tab) {
        self.active_tab = new_tab;

        // When switching to History tab, refresh history for currently selected account
        if new_tab == Tab::History {
            let accounts = &self.accounts_component.accounts;
            let selected_index = self.accounts_component.selected_index;
            if let Some(account) = accounts.get(selected_index) {
                // Update history component's account to match selected account
                self.history_component.set_account(Some(account.clone()));
                // Load history for this account
                if let Ok(history) = self.store.get_tx_history(account.id) {
                    self.history_component.set_transactions(history);
                }
            }
        }
    }

    /// Handle background scan progress updates.
    fn handle_scan_update(&mut self, update: crate::infra::scanner::ScanUpdate) -> Result<()> {
        use crate::infra::scanner::ScanUpdate;

        match update {
            ScanUpdate::Started { is_full_rescan } => {
                if is_full_rescan {
                    self.status_message = "Full rescan started...".to_string();
                } else {
                    self.status_message = "Scanning...".to_string();
                }
            }
            ScanUpdate::CellScanProgress {
                cells_scanned,
                cells_matched,
            } => {
                self.status_message = format!(
                    "Scanning cells: {} scanned, {} matched",
                    cells_scanned, cells_matched
                );
            }
            ScanUpdate::CellScanComplete {
                stealth_cells_found,
                ct_cells_found,
            } => {
                self.status_message = format!(
                    "Cells found: {} stealth, {} CT. Scanning history...",
                    stealth_cells_found, ct_cells_found
                );
            }
            ScanUpdate::HistoryScanProgress {
                txs_processed,
                total_txs,
            } => {
                // txs_processed = transactions checked, total_txs = relevant transactions found
                self.status_message = format!(
                    "Scanning history: {} checked, {} found",
                    txs_processed, total_txs
                );
            }
            ScanUpdate::Complete {
                total_stealth_cells,
                total_ct_cells,
                total_tx_records,
            } => {
                self.is_scanning = false;
                self.scan_update_rx = None;

                // Refresh all UI components
                self.refresh_after_scan()?;

                // Calculate total capacity from stealth cells
                let accounts = self.account_manager.list_accounts()?;
                let mut total_capacity = 0u64;
                for account in &accounts {
                    if let Ok(cells) = self.store.get_stealth_cells(account.id) {
                        let capacity: u64 = cells.iter().map(|c| c.capacity).sum();
                        total_capacity += capacity;
                        // Update account balance
                        let _ = self.account_manager.update_balance(account.id, capacity);
                    }
                }

                let ckb_amount = total_capacity as f64 / 100_000_000.0;
                self.status_message = format!(
                    "Scan complete: {} stealth, {} CT cells, {} tx records, {:.4} CKB",
                    total_stealth_cells, total_ct_cells, total_tx_records, ckb_amount
                );

                // Refresh accounts display with updated balances
                self.accounts_component
                    .set_accounts(self.account_manager.list_accounts()?);

                if let Ok(tip) = self.scanner.get_tip_block_number() {
                    self.tip_block_number = Some(tip);
                }
            }
            ScanUpdate::Error(msg) => {
                self.is_scanning = false;
                self.scan_update_rx = None;
                self.status_message = format!("Scan error: {}", msg);
                info!("Background scan error: {}", msg);
            }
        }
        Ok(())
    }

    /// Refresh UI components after a scan completes.
    fn refresh_after_scan(&mut self) -> Result<()> {
        // Refresh accounts list
        let updated_accounts = self.account_manager.list_accounts()?;
        self.accounts_component
            .set_accounts(updated_accounts.clone());

        // Refresh send component's account balance
        if let Some(ref current_account) = self.send_component.account {
            if let Some(updated) = updated_accounts.iter().find(|a| a.id == current_account.id) {
                self.send_component.set_account(Some(updated.clone()));
            }
        }

        // Refresh receive component's account
        if let Some(ref current_account) = self.receive_component.account {
            if let Some(updated) = updated_accounts.iter().find(|a| a.id == current_account.id) {
                self.receive_component.set_account(Some(updated.clone()));
            }
        }

        // Refresh history component
        let history_account_id = self.history_component.account.as_ref().map(|a| a.id);
        if let Some(account_id) = history_account_id {
            if let Some(updated) = updated_accounts.iter().find(|a| a.id == account_id) {
                self.history_component.set_account(Some(updated.clone()));
            }
            // Reload transaction history
            if let Ok(history) = self.store.get_tx_history(account_id) {
                self.history_component.set_transactions(history);
            }
        }

        // Refresh tokens display for current account
        if let Some(ref current_account) = self.tokens_component.account.clone() {
            // Update tokens component's account
            if let Some(updated) = updated_accounts.iter().find(|a| a.id == current_account.id) {
                self.tokens_component.set_account(Some(updated.clone()));
            }

            if let Ok(ct_cells) = self.store.get_ct_cells(current_account.id) {
                let ct_info_cells = self
                    .store
                    .get_ct_info_cells(current_account.id)
                    .unwrap_or_default();
                let balances =
                    aggregate_ct_balances_with_info(&ct_cells, &ct_info_cells, &self.config);
                self.tokens_component.set_balances(balances);
                self.tokens_component.set_ct_cells(ct_cells);
            }
        }

        Ok(())
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
            Event::Mouse(mouse_event) => {
                if mouse_event.kind == MouseEventKind::Down(MouseButton::Left) {
                    self.handle_mouse_click(mouse_event.column, mouse_event.row)?;
                }
            }
            Event::Paste(text) => {
                self.handle_paste(&text)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()> {
        // Handle wallet setup mode - route all key events to wallet setup component
        if self.mode == AppMode::WalletSetup {
            // Only allow Ctrl+C to quit
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                self.action_tx.send(Action::Quit)?;
                return Ok(());
            }
            // Route to wallet setup component
            self.wallet_setup_component.handle_key_event(key)?;
            return Ok(());
        }

        // Normal mode
        // Check if we're in an input mode that should capture all keystrokes
        let is_editing = match self.active_tab {
            Tab::Send => {
                self.send_component.is_editing
                    || self.send_component.mode == SendMode::EnteringPassphrase
            }
            Tab::Settings => {
                self.settings_component.mode == SettingsMode::EnteringPassphraseForExport
                    || self.settings_component.mode == SettingsMode::EnteringPassphraseForCreate
            }
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
                Tab::Settings => {
                    self.settings_component.handle_key_event(key)?;
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
            KeyCode::Char('q' | 'Q') if key.modifiers.is_empty() => {
                self.action_tx.send(Action::Quit)?;
            }
            KeyCode::Char('z') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.action_tx.send(Action::Suspend)?;
            }
            KeyCode::Tab => {
                let tabs = Tab::all(self.dev_mode);
                let next_index = (self.active_tab.index(self.dev_mode) + 1) % tabs.len();
                self.switch_tab(Tab::from_index(next_index, self.dev_mode));
            }
            KeyCode::BackTab => {
                let tabs = Tab::all(self.dev_mode);
                let prev_index = if self.active_tab.index(self.dev_mode) == 0 {
                    tabs.len() - 1
                } else {
                    self.active_tab.index(self.dev_mode) - 1
                };
                self.switch_tab(Tab::from_index(prev_index, self.dev_mode));
            }
            // Tab hotkeys for quick navigation (case-insensitive)
            KeyCode::Char('g' | 'G') if key.modifiers.is_empty() => {
                self.switch_tab(Tab::Settings);
            }
            KeyCode::Char('a' | 'A') if key.modifiers.is_empty() => {
                self.switch_tab(Tab::Accounts);
            }
            KeyCode::Char('s' | 'S') if key.modifiers.is_empty() => {
                self.switch_tab(Tab::Send);
            }
            KeyCode::Char('r' | 'R') if key.modifiers.is_empty() => {
                self.switch_tab(Tab::Receive);
            }
            KeyCode::Char('t' | 'T') if key.modifiers.is_empty() => {
                self.switch_tab(Tab::Tokens);
            }
            KeyCode::Char('h' | 'H') if key.modifiers.is_empty() => {
                self.switch_tab(Tab::History);
            }
            KeyCode::Char('d' | 'D') if key.modifiers.is_empty() && self.dev_mode => {
                self.switch_tab(Tab::Dev);
            }
            // Global hotkey: F for Full Rescan (case-insensitive)
            KeyCode::Char('f' | 'F') if key.modifiers.is_empty() => {
                self.action_tx.send(Action::FullRescan)?;
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
        // Handle wallet setup mode paste
        if self.mode == AppMode::WalletSetup {
            self.wallet_setup_component.paste(text);
            return Ok(());
        }

        // Normal mode paste
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

    fn handle_mouse_click(&mut self, col: u16, row: u16) -> Result<()> {
        let area = self.tab_area;
        // Check if click is within the tab bar (excluding borders)
        if row < area.y + 1 || row > area.y + area.height.saturating_sub(2) {
            return Ok(());
        }
        if col < area.x + 1 || col >= area.x + area.width.saturating_sub(1) {
            return Ok(());
        }

        // Calculate which tab was clicked.
        // Ratatui Tabs renders as: ` Title1 │ Title2 │ Title3 `
        // Each tab takes: 1 (pad) + title_width + 1 (pad) + 1 (divider)
        // except the last tab has no trailing divider.
        let tabs = Tab::all(self.dev_mode);
        let rel_x = (col - area.x - 1) as usize; // relative x within inner area
        let mut offset = 0usize;
        for (i, tab) in tabs.iter().enumerate() {
            let title_width = tab.title().width();
            let tab_width = 1 + title_width + 1; // space + title + space
            if rel_x < offset + tab_width {
                self.switch_tab(*tab);
                return Ok(());
            }
            offset += tab_width;
            if i < tabs.len() - 1 {
                offset += 1; // divider "│" is 1 column wide (in ratatui default)
            }
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

                // Check for background scan updates
                let mut updates = Vec::new();
                if let Some(ref mut rx) = self.scan_update_rx {
                    while let Ok(update) = rx.try_recv() {
                        updates.push(update);
                    }
                }
                for update in updates {
                    self.handle_scan_update(update)?;
                }

                // Auto-scan for new cells every 5 seconds (if not already scanning)
                let auto_scan_interval = 5u64;
                let should_auto_scan = !self.is_scanning
                    && self
                        .last_auto_scan
                        .map(|last| now >= last + auto_scan_interval)
                        .unwrap_or(true);

                if should_auto_scan {
                    let accounts = self.account_manager.list_accounts()?;
                    if !accounts.is_empty() {
                        // Start background auto-scan
                        self.is_scanning = true;
                        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                        self.scan_update_rx = Some(rx);

                        Scanner::spawn_background_scan(
                            self.config.clone(),
                            self.store.clone(),
                            accounts,
                            false, // incremental scan
                            tx,
                        );
                    }
                    // Update timestamp immediately so we don't spam scans
                    self.last_auto_scan = Some(now);
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
            Action::ScanProgress(update) => {
                self.handle_scan_update(update)?;
            }
            Action::Quit => {
                self.should_quit = true;
            }
            Action::Suspend => {
                self.should_suspend = true;
            }
            Action::CreateAccount => {
                // This action is no longer used directly - we use CreateAccountWithPassphrase
                // The settings component now prompts for passphrase before creating account
            }
            Action::CreateAccountWithPassphrase(ref passphrase) => {
                // Wallet should already exist at this point
                let wallet_meta = match &mut self.wallet_meta {
                    Some(meta) => meta,
                    None => {
                        self.settings_component.error_message =
                            Some("Wallet not initialized".to_string());
                        self.status_message = "Error: Wallet not initialized".to_string();
                        return Ok(());
                    }
                };

                let account = match self.account_manager.create_account(
                    format!(
                        "Account {}",
                        self.account_manager.list_accounts()?.len() + 1
                    ),
                    wallet_meta,
                    passphrase,
                ) {
                    Ok(acc) => acc,
                    Err(e) => {
                        self.settings_component.error_message =
                            Some(format!("Invalid passphrase: {}", e));
                        return Ok(());
                    }
                };

                // Clear passphrase input and return to menu mode
                self.settings_component.passphrase_input.clear();
                self.settings_component.mode =
                    crate::components::settings::SettingsMode::Menu;

                let accounts = self.account_manager.list_accounts()?;
                let new_index = accounts.len().saturating_sub(1);

                // Update accounts list and select the new account
                self.accounts_component.set_accounts(accounts);
                self.accounts_component.select(new_index);
                self.account_manager.set_active_account(new_index)?;

                // Update all components with the new account
                self.receive_component.set_account(Some(account.clone()));
                self.send_component.set_account(Some(account.clone()));
                self.history_component.set_account(Some(account.clone()));
                self.tokens_component.set_account(Some(account.clone()));
                if let Some(ref mut dev) = self.dev_component {
                    dev.set_account(Some(account.clone()));
                }

                self.switch_tab(Tab::Accounts);
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
                        let balances = aggregate_ct_balances_with_info(
                            &ct_cells,
                            &ct_info_cells,
                            &self.config,
                        );
                        self.tokens_component.set_ct_cells(ct_cells);
                        self.tokens_component.set_balances(balances);
                    }
                }
                self.status_message = format!("Selected Account {}", index + 1);
            }
            Action::Rescan => {
                if self.is_scanning {
                    self.status_message = "Scan already in progress...".to_string();
                    return Ok(());
                }

                let accounts = self.account_manager.list_accounts()?;
                if accounts.is_empty() {
                    self.status_message = "No accounts to scan".to_string();
                    return Ok(());
                }

                // Start background scan
                self.status_message = "Scanning in background...".to_string();
                self.is_scanning = true;

                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                self.scan_update_rx = Some(rx);

                Scanner::spawn_background_scan(
                    self.config.clone(),
                    self.store.clone(),
                    accounts,
                    false, // incremental scan
                    tx,
                );
            }
            Action::FullRescan => {
                if self.is_scanning {
                    self.status_message = "Scan already in progress...".to_string();
                    return Ok(());
                }

                let accounts = self.account_manager.list_accounts()?;
                if accounts.is_empty() {
                    self.status_message = "No accounts to scan".to_string();
                    return Ok(());
                }

                // Start background full rescan
                self.status_message = "Full rescan in background...".to_string();
                self.is_scanning = true;

                let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
                self.scan_update_rx = Some(rx);

                Scanner::spawn_background_scan(
                    self.config.clone(),
                    self.store.clone(),
                    accounts,
                    true, // full rescan
                    tx,
                );
            }
            Action::SendTransaction => {
                // This action is no longer used directly - we use SendTransactionWithPassphrase
                // The send component now prompts for passphrase before sending
            }
            Action::SendTransactionWithPassphrase(ref passphrase) => {
                // Get send parameters
                let recipient = self.send_component.recipient.clone();
                let amount = self.send_component.parse_amount();
                let address_type = self.send_component.detect_address_type();

                if let (Some(ref account), Some(amount_shannon)) =
                    (self.send_component.account.clone(), amount)
                {
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

                    // Build the transaction based on address type
                    let builder = StealthTxBuilder::new(self.config.clone());
                    let builder = match address_type {
                        AddressType::Stealth => {
                            // Parse the recipient stealth address
                            let stealth_addr = match parse_stealth_address(&recipient) {
                                Ok(addr) => addr,
                                Err(e) => {
                                    self.send_component.error_message =
                                        Some(format!("Invalid stealth address: {}", e));
                                    self.status_message =
                                        "Send failed: invalid address".to_string();
                                    return Ok(());
                                }
                            };
                            builder.add_output(stealth_addr, amount_shannon)
                        }
                        AddressType::Ckb => {
                            // Use the CKB address directly
                            match builder.add_ckb_output_with_capacity(&recipient, amount_shannon) {
                                Ok(b) => b,
                                Err(e) => {
                                    self.send_component.error_message =
                                        Some(format!("Invalid CKB address: {}", e));
                                    self.status_message =
                                        "Send failed: invalid address".to_string();
                                    return Ok(());
                                }
                            }
                        }
                        AddressType::Unknown => {
                            self.send_component.error_message =
                                Some("Invalid recipient address format".to_string());
                            self.status_message = "Send failed: invalid address".to_string();
                            return Ok(());
                        }
                    };

                    let builder = match builder.select_inputs(&available_cells, amount_shannon) {
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

                    // Sign the transaction using provided passphrase
                    let wallet_meta = match &self.wallet_meta {
                        Some(meta) => meta,
                        None => {
                            self.send_component.error_message =
                                Some("Wallet not initialized".to_string());
                            self.status_message = "Send failed: no wallet".to_string();
                            return Ok(());
                        }
                    };

                    let spend_key_bytes = match account.decrypt_spend_key(wallet_meta, passphrase) {
                        Ok(key) => key,
                        Err(e) => {
                            self.send_component.error_message =
                                Some(format!("Invalid passphrase: {}", e));
                            return Ok(());
                        }
                    };

                    let spend_key = match secp256k1::SecretKey::from_slice(&*spend_key_bytes) {
                        Ok(key) => key,
                        Err(e) => {
                            self.send_component.error_message =
                                Some(format!("Invalid spend key: {}", e));
                            self.status_message = "Send failed: key error".to_string();
                            return Ok(());
                        }
                    };

                    let signed_tx = match StealthTxBuilder::sign(
                        built_tx.clone(),
                        account,
                        &spend_key,
                        &input_cells,
                    ) {
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
                            let tx_hash_hex = hex::encode(&tx_hash.0);
                            self.send_component.success_message =
                                Some(format!("Sent {:.8} CKB! Tx: 0x{}", amount_ckb, tx_hash_hex));
                            self.status_message = format!(
                                "Sent {:.8} CKB (tx: 0x{}...{})",
                                amount_ckb,
                                &tx_hash_hex[..8],
                                &tx_hash_hex[56..]
                            );

                            // Note: Transaction history is now derived from on-chain data,
                            // not recorded at send time. History will update after rescan.

                            // Remove spent cells from store
                            let spent_out_points: Vec<_> =
                                input_cells.iter().map(|c| c.out_point.clone()).collect();
                            if let Err(e) =
                                self.store.remove_spent_cells(account.id, &spent_out_points)
                            {
                                info!("Failed to remove spent cells: {}", e);
                            }

                            // Clear send form and passphrase
                            self.send_component.recipient.clear();
                            self.send_component.amount.clear();
                            self.send_component.focused_field =
                                crate::components::send::SendField::Recipient;
                            self.send_component.is_editing = false;
                            self.send_component.error_message = None;
                            self.send_component.mode = SendMode::Form;
                            self.send_component.passphrase_input.clear();
                            // Note: success_message is kept to show the tx hash to user
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
                // No-op: passphrase flow now handled via TransferTokenWithPassphrase
            }
            Action::MintToken => {
                // No-op: passphrase flow now handled via MintTokenWithPassphrase
            }
            Action::CreateToken => {
                // No-op: passphrase flow now handled via CreateTokenWithPassphrase
            }
            Action::TransferTokenWithPassphrase(ref passphrase) => {
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

                    // Filter CT cells to only those matching the selected token
                    let matching_ct_cells: Vec<_> = available_ct_cells
                        .iter()
                        .filter(|c| c.type_script_args == token_balance.type_script_args)
                        .cloned()
                        .collect();

                    if matching_ct_cells.is_empty() {
                        self.tokens_component.error_message =
                            Some("No CT cells for selected token".to_string());
                        self.status_message = "CT transfer failed: no matching cells".to_string();
                        return Ok(());
                    }

                    // Get stealth cells (CKB) to use as funding for the transfer
                    // CT transfers may need extra capacity for change outputs
                    let stealth_cells = match self.store.get_stealth_cells(account.id) {
                        Ok(cells) => cells,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Failed to get stealth cells: {}", e));
                            self.status_message = "CT transfer failed: storage error".to_string();
                            return Ok(());
                        }
                    };

                    // Find a funding cell with enough capacity (255 CKB + fees)
                    const MIN_FUNDING_CAPACITY: u64 = 256_00000000; // 256 CKB
                    let funding_cell = stealth_cells
                        .iter()
                        .find(|c| c.capacity >= MIN_FUNDING_CAPACITY);

                    // Build the CT transaction
                    let mut builder = CtTxBuilder::new(
                        self.config.clone(),
                        token_balance.type_script_args.clone(),
                    );

                    // Add funding cell if available
                    let funding_input = if let Some(fc) = funding_cell {
                        let funding = FundingCell {
                            out_point: fc.out_point.clone(),
                            capacity: fc.capacity,
                            lock_script_args: fc.stealth_script_args.clone(),
                        };
                        builder = builder.funding_cell(funding.clone());
                        Some(funding)
                    } else {
                        None
                    };

                    let builder = match builder
                        .add_output(stealth_addr, amount_value)
                        .select_inputs(&matching_ct_cells, amount_value)
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

                    // Sign the transaction using provided passphrase
                    let wallet_meta = self
                        .wallet_meta
                        .as_ref()
                        .ok_or_else(|| color_eyre::eyre::eyre!("Wallet not initialized"))?;
                    let spend_key_bytes = match account.decrypt_spend_key(wallet_meta, passphrase) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Invalid passphrase: {}", e));
                            self.status_message =
                                "CT transfer failed: invalid passphrase".to_string();
                            return Ok(());
                        }
                    };
                    let spend_key = secp256k1::SecretKey::from_slice(&*spend_key_bytes)
                        .map_err(|e| color_eyre::eyre::eyre!("Invalid spend key: {}", e))?;

                    let funding_lock_args = funding_input
                        .as_ref()
                        .map(|f| f.lock_script_args.as_slice());
                    let signed_tx = match CtTxBuilder::sign(
                        built_tx.clone(),
                        account,
                        &spend_key,
                        &input_cells,
                        funding_lock_args,
                    ) {
                        Ok(tx) => tx,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Signing failed: {}", e));
                            self.status_message = "CT transfer failed: signing error".to_string();
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

                            // Remove spent CT cells from store
                            let spent_out_points: Vec<_> =
                                input_cells.iter().map(|c| c.out_point.clone()).collect();
                            if let Err(e) = self
                                .store
                                .remove_spent_ct_cells(account.id, &spent_out_points)
                            {
                                info!("Failed to remove spent CT cells: {}", e);
                            }

                            // Remove spent funding cell from store (if used)
                            if let Some(ref fc) = funding_input
                                && let Err(e) = self.store.remove_spent_cells(
                                    account.id,
                                    std::slice::from_ref(&fc.out_point),
                                )
                            {
                                info!("Failed to remove spent funding cell: {}", e);
                            }

                            // Refresh CT balances
                            if let Ok(ct_cells) = self.store.get_ct_cells(account.id) {
                                let ct_info_cells =
                                    self.store.get_ct_info_cells(account.id).unwrap_or_default();
                                let balances = aggregate_ct_balances_with_info(
                                    &ct_cells,
                                    &ct_info_cells,
                                    &self.config,
                                );
                                self.tokens_component.set_balances(balances);
                                self.tokens_component.set_ct_cells(ct_cells);
                            }

                            // Clear transfer form and passphrase
                            self.tokens_component.clear_transfer();
                            self.tokens_component.passphrase_input.clear();
                            self.tokens_component.pending_action = None;
                            self.tokens_component.mode =
                                crate::components::tokens::TokensMode::List;
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
            Action::MintTokenWithPassphrase(ref passphrase) => {
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

                    let funding_cell = stealth_cells
                        .iter()
                        .find(|c| c.capacity >= min_funding_capacity);

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

                    // Sign the transaction using provided passphrase
                    let wallet_meta = self
                        .wallet_meta
                        .as_ref()
                        .ok_or_else(|| color_eyre::eyre::eyre!("Wallet not initialized"))?;
                    let spend_key_bytes = match account.decrypt_spend_key(wallet_meta, passphrase) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Invalid passphrase: {}", e));
                            self.status_message = "CT mint failed: invalid passphrase".to_string();
                            return Ok(());
                        }
                    };
                    let spend_key = secp256k1::SecretKey::from_slice(&*spend_key_bytes)
                        .map_err(|e| color_eyre::eyre::eyre!("Invalid spend key: {}", e))?;

                    let signed_tx = match sign_mint_transaction(
                        built_tx,
                        account,
                        &spend_key,
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

                            // Remove spent funding cell from store
                            if let Err(e) = self.store.remove_spent_cells(
                                account.id,
                                std::slice::from_ref(&funding_input.out_point),
                            ) {
                                info!("Failed to remove spent funding cell: {}", e);
                            }

                            // Clear mint form and passphrase
                            self.tokens_component.clear_mint();
                            self.tokens_component.passphrase_input.clear();
                            self.tokens_component.pending_action = None;
                            self.tokens_component.mode =
                                crate::components::tokens::TokensMode::List;
                        }
                        Err(e) => {
                            // Enhanced error logging for troubleshooting
                            let error_str = format!("{}", e);
                            tracing::error!(
                                "CT mint submission failed: {}\n  \
                                 Hint: If this is 'InvalidRangeProof' (error 9), possible causes:\n  \
                                 - Contract version mismatch (redeploy contracts or check config)\n  \
                                 - Bulletproofs library version mismatch\n  \
                                 Run with RUST_LOG=debug for detailed diagnostics.",
                                error_str
                            );
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
            Action::CreateTokenWithPassphrase(ref passphrase) => {
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

                    // Sign the transaction using provided passphrase
                    let wallet_meta = self
                        .wallet_meta
                        .as_ref()
                        .ok_or_else(|| color_eyre::eyre::eyre!("Wallet not initialized"))?;
                    let spend_key_bytes = match account.decrypt_spend_key(wallet_meta, passphrase) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            self.tokens_component.error_message =
                                Some(format!("Invalid passphrase: {}", e));
                            self.status_message = "Genesis failed: invalid passphrase".to_string();
                            return Ok(());
                        }
                    };
                    let spend_key = secp256k1::SecretKey::from_slice(&*spend_key_bytes)
                        .map_err(|e| color_eyre::eyre::eyre!("Invalid spend key: {}", e))?;

                    let signed_tx = match sign_genesis_transaction(
                        built_tx,
                        account,
                        &spend_key,
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

                            // Remove spent stealth cell from store
                            if let Err(e) = self.store.remove_spent_cells(
                                account.id,
                                std::slice::from_ref(&funding_cell.out_point),
                            ) {
                                info!("Failed to remove spent stealth cell: {}", e);
                            }

                            // Trigger a rescan to detect the new ct-info cell
                            self.status_message
                                .push_str(" - Press 'r' to rescan after confirmation");

                            // Refresh CT balances to show updated state
                            if let Ok(ct_cells) = self.store.get_ct_cells(account.id) {
                                let ct_info_cells =
                                    self.store.get_ct_info_cells(account.id).unwrap_or_default();
                                let balances = aggregate_ct_balances_with_info(
                                    &ct_cells,
                                    &ct_info_cells,
                                    &self.config,
                                );
                                self.tokens_component.set_balances(balances);
                                self.tokens_component.set_ct_cells(ct_cells);
                            }

                            // Clear genesis form, passphrase, and return to list
                            self.tokens_component.clear_genesis();
                            self.tokens_component.passphrase_input.clear();
                            self.tokens_component.pending_action = None;
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
                self.switch_tab(Tab::Dev);
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

                if let (Some(faucet), Some(amount), Some(account)) = (&self.faucet, amount, account)
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
                    let stealth_lock_code_hash = match ckb_types::H256::from_slice(&code_hash_bytes)
                    {
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
            Action::ExportWalletBackup => {
                // This action is no longer used directly - we use ExportWalletBackupWithPassphrase
                // But keep it for backwards compatibility, it will just show an error
                self.settings_component.error_message =
                    Some("Please use passphrase input to export".to_string());
            }
            Action::ExportWalletBackupWithPassphrase(ref passphrase) => {
                // Export wallet backup string with provided passphrase
                match &self.wallet_meta {
                    Some(wallet_meta) => {
                        // Verify the passphrase first by trying to decrypt mnemonic
                        match crate::domain::wallet::decrypt_mnemonic(wallet_meta, passphrase) {
                            Ok(mnemonic) => {
                                // Get account count
                                let account_count =
                                    self.account_manager.list_accounts()?.len() as u32;
                                match crate::domain::wallet::export_wallet(
                                    &mnemonic,
                                    account_count,
                                    passphrase,
                                ) {
                                    Ok(backup_string) => {
                                        self.settings_component.passphrase_input.clear();
                                        self.settings_component.set_backup_string(backup_string);
                                        self.settings_component.error_message = None;
                                    }
                                    Err(e) => {
                                        self.settings_component.error_message =
                                            Some(format!("Export failed: {}", e));
                                    }
                                }
                            }
                            Err(e) => {
                                self.settings_component.error_message =
                                    Some(format!("Invalid passphrase: {}", e));
                            }
                        }
                    }
                    None => {
                        self.settings_component.error_message =
                            Some("Wallet not initialized".to_string());
                    }
                }
            }
            Action::SaveBackupToFile(ref backup_string) => {
                // Save backup string to a file in the current directory
                let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
                let filename = format!("obscell-encrypted-keystore-{}.txt", timestamp);
                match std::fs::write(&filename, backup_string) {
                    Ok(()) => {
                        self.settings_component.success_message =
                            Some(format!("Backup saved to: {}", filename));
                        // Close the backup overlay and return to menu
                        self.settings_component.mode = SettingsMode::Menu;
                        self.settings_component.backup_string = None;
                    }
                    Err(e) => {
                        self.settings_component.error_message =
                            Some(format!("Failed to save backup: {}", e));
                    }
                }
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
                self.settings_component
                    .set_network(&self.config.network.name);

                // Reset UI components with the first account (if any)
                // First update receive component's config for the new network
                self.receive_component.set_config(new_config);

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
                    let miner_key_bytes = hex::decode(
                        "d00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc",
                    )
                    .expect("Invalid miner key hex");
                    let miner_key = secp256k1::SecretKey::from_slice(&miner_key_bytes)
                        .expect("Invalid miner key");
                    let miner_lock_args = Faucet::derive_lock_args(&miner_key);
                    let faucet =
                        Faucet::new(&self.config.network.rpc_url, miner_key, miner_lock_args);

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
                        self.switch_tab(Tab::Settings);
                    }
                }

                self.dev_mode = new_dev_mode;

                // Save network preference to global store
                if let Ok(global_store) = Store::global() {
                    let _ =
                        global_store.save_metadata(SELECTED_NETWORK_KEY, &self.config.network.name);
                }

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
            // Wallet setup actions
            Action::GenerateMnemonic => {
                // Generate a new mnemonic and set it in the component
                let mnemonic = crate::domain::wallet::generate_mnemonic();
                self.wallet_setup_component.set_mnemonic(mnemonic.phrase());
                self.wallet_setup_component.mode = SetupMode::ShowMnemonic;
            }
            Action::CreateWallet => {
                // Create wallet from mnemonic and passphrase
                let mnemonic_str = self.wallet_setup_component.get_mnemonic();
                let passphrase = self.wallet_setup_component.get_passphrase().to_string();

                // Parse mnemonic first
                let mnemonic = match crate::domain::wallet::parse_mnemonic(&mnemonic_str) {
                    Ok(m) => m,
                    Err(e) => {
                        self.wallet_setup_component.error_message =
                            Some(format!("Invalid mnemonic: {}", e));
                        return Ok(());
                    }
                };

                match crate::domain::wallet::create_wallet_meta(&mnemonic, &passphrase) {
                    Ok(mut meta) => {
                        // Save to store
                        if let Err(e) = self.store.save_wallet_meta(&meta) {
                            self.wallet_setup_component.error_message =
                                Some(format!("Failed to save wallet: {}", e));
                            return Ok(());
                        }

                        // Automatically create the first account
                        let account = match self.account_manager.create_account(
                            "Account 1".to_string(),
                            &mut meta,
                            &passphrase,
                        ) {
                            Ok(acc) => acc,
                            Err(e) => {
                                self.wallet_setup_component.error_message =
                                    Some(format!("Failed to create account: {}", e));
                                return Ok(());
                            }
                        };

                        // Update wallet meta after account creation (next_account_index changed)
                        if let Err(e) = self.store.save_wallet_meta(&meta) {
                            self.wallet_setup_component.error_message =
                                Some(format!("Failed to save wallet: {}", e));
                            return Ok(());
                        }

                        // Update app state
                        self.wallet_meta = Some(meta);

                        // Update accounts list
                        let accounts = self.account_manager.list_accounts().unwrap_or_default();
                        self.accounts_component.set_accounts(accounts);
                        self.accounts_component.select(0);
                        self.account_manager.set_active_account(0).ok();

                        // Update all components with the new account
                        self.receive_component.set_account(Some(account.clone()));
                        self.send_component.set_account(Some(account.clone()));
                        self.history_component.set_account(Some(account.clone()));
                        self.tokens_component.set_account(Some(account.clone()));
                        if let Some(ref mut dev) = self.dev_component {
                            dev.set_account(Some(account));
                        }

                        // Switch to normal mode and show Accounts tab
                        self.mode = AppMode::Normal;
                        self.switch_tab(Tab::Accounts);
                        self.wallet_setup_component.reset();
                        self.status_message = "Wallet created with Account 1!".to_string();
                    }
                    Err(e) => {
                        self.wallet_setup_component.error_message =
                            Some(format!("Failed to create wallet: {}", e));
                    }
                }
            }
            Action::RestoreFromMnemonic => {
                // Restore wallet from mnemonic
                let mnemonic_str = self.wallet_setup_component.get_mnemonic();
                let passphrase = self.wallet_setup_component.get_passphrase().to_string();

                // Parse and validate mnemonic first
                let mnemonic = match crate::domain::wallet::parse_mnemonic(&mnemonic_str) {
                    Ok(m) => m,
                    Err(e) => {
                        self.wallet_setup_component.error_message =
                            Some(format!("Invalid mnemonic: {}", e));
                        return Ok(());
                    }
                };

                match crate::domain::wallet::create_wallet_meta(&mnemonic, &passphrase) {
                    Ok(mut meta) => {
                        // Save to store
                        if let Err(e) = self.store.save_wallet_meta(&meta) {
                            self.wallet_setup_component.error_message =
                                Some(format!("Failed to save wallet: {}", e));
                            return Ok(());
                        }

                        // Automatically create the first account
                        let account = match self.account_manager.create_account(
                            "Account 1".to_string(),
                            &mut meta,
                            &passphrase,
                        ) {
                            Ok(acc) => acc,
                            Err(e) => {
                                self.wallet_setup_component.error_message =
                                    Some(format!("Failed to create account: {}", e));
                                return Ok(());
                            }
                        };

                        // Update wallet meta after account creation (next_account_index changed)
                        if let Err(e) = self.store.save_wallet_meta(&meta) {
                            self.wallet_setup_component.error_message =
                                Some(format!("Failed to save wallet: {}", e));
                            return Ok(());
                        }

                        // Update app state
                        self.wallet_meta = Some(meta);

                        // Update accounts list
                        let accounts = self.account_manager.list_accounts().unwrap_or_default();
                        self.accounts_component.set_accounts(accounts);
                        self.accounts_component.select(0);
                        self.account_manager.set_active_account(0).ok();

                        // Update all components with the new account
                        self.receive_component.set_account(Some(account.clone()));
                        self.send_component.set_account(Some(account.clone()));
                        self.history_component.set_account(Some(account.clone()));
                        self.tokens_component.set_account(Some(account.clone()));
                        if let Some(ref mut dev) = self.dev_component {
                            dev.set_account(Some(account));
                        }

                        // Switch to normal mode and show Accounts tab
                        self.mode = AppMode::Normal;
                        self.switch_tab(Tab::Accounts);
                        self.wallet_setup_component.reset();
                        self.status_message = "Wallet restored with Account 1!".to_string();
                    }
                    Err(e) => {
                        self.wallet_setup_component.error_message =
                            Some(format!("Failed to restore wallet: {}", e));
                    }
                }
            }
            Action::RestoreFromBackup => {
                // Restore wallet from backup string
                let backup_string = self.wallet_setup_component.get_backup_input().to_string();
                let passphrase = self.wallet_setup_component.get_passphrase().to_string();

                // Import returns (mnemonic, account_count)
                match crate::domain::wallet::import_wallet(&backup_string, &passphrase) {
                    Ok((mnemonic, _account_count)) => {
                        // Create wallet meta from the imported mnemonic
                        match crate::domain::wallet::create_wallet_meta(&mnemonic, &passphrase) {
                            Ok(mut meta) => {
                                // Save to store
                                if let Err(e) = self.store.save_wallet_meta(&meta) {
                                    self.wallet_setup_component.error_message =
                                        Some(format!("Failed to save wallet: {}", e));
                                    return Ok(());
                                }

                                // Automatically create the first account
                                let account = match self.account_manager.create_account(
                                    "Account 1".to_string(),
                                    &mut meta,
                                    &passphrase,
                                ) {
                                    Ok(acc) => acc,
                                    Err(e) => {
                                        self.wallet_setup_component.error_message =
                                            Some(format!("Failed to create account: {}", e));
                                        return Ok(());
                                    }
                                };

                                // Update wallet meta after account creation (next_account_index changed)
                                if let Err(e) = self.store.save_wallet_meta(&meta) {
                                    self.wallet_setup_component.error_message =
                                        Some(format!("Failed to save wallet: {}", e));
                                    return Ok(());
                                }

                                // Update app state
                                self.wallet_meta = Some(meta);

                                // Update accounts list
                                let accounts =
                                    self.account_manager.list_accounts().unwrap_or_default();
                                self.accounts_component.set_accounts(accounts);
                                self.accounts_component.select(0);
                                self.account_manager.set_active_account(0).ok();

                                // Update all components with the new account
                                self.receive_component.set_account(Some(account.clone()));
                                self.send_component.set_account(Some(account.clone()));
                                self.history_component.set_account(Some(account.clone()));
                                self.tokens_component.set_account(Some(account.clone()));
                                if let Some(ref mut dev) = self.dev_component {
                                    dev.set_account(Some(account));
                                }

                                // Switch to normal mode and show Accounts tab
                                self.mode = AppMode::Normal;
                                self.switch_tab(Tab::Accounts);
                                self.wallet_setup_component.reset();
                                self.status_message =
                                    "Wallet restored from backup with Account 1!".to_string();
                            }
                            Err(e) => {
                                self.wallet_setup_component.error_message =
                                    Some(format!("Failed to create wallet from import: {}", e));
                            }
                        }
                    }
                    Err(e) => {
                        self.wallet_setup_component.error_message =
                            Some(format!("Failed to restore from backup: {}", e));
                    }
                }
            }
            Action::WalletSetupComplete => {
                // Switch to normal mode (in case it's manually triggered)
                self.mode = AppMode::Normal;
                self.wallet_setup_component.reset();
            }
            _ => {}
        }
        Ok(())
    }

    fn draw_ui(&mut self) -> Result<()> {
        // Handle wallet setup mode separately - simpler rendering
        if self.mode == AppMode::WalletSetup {
            // Extract wallet setup data
            let setup_mode = self.wallet_setup_component.mode;
            let setup_selected_menu = self.wallet_setup_component.selected_menu;
            let setup_passphrase = self.wallet_setup_component.passphrase.clone();
            let setup_passphrase_confirm = self.wallet_setup_component.passphrase_confirm.clone();
            let setup_show_passphrase = self.wallet_setup_component.show_passphrase;
            let setup_mnemonic_words = self.wallet_setup_component.mnemonic_words.clone();
            let setup_mnemonic_input = self.wallet_setup_component.mnemonic_input.clone();
            let setup_backup_input = self.wallet_setup_component.backup_input.clone();
            let setup_error_message = self.wallet_setup_component.error_message.clone();
            let setup_success_message = self.wallet_setup_component.success_message.clone();

            self.tui.draw(|f| {
                WalletSetupComponent::draw_static(
                    f,
                    f.area(),
                    setup_mode,
                    setup_selected_menu,
                    &setup_passphrase,
                    &setup_passphrase_confirm,
                    setup_show_passphrase,
                    &setup_mnemonic_words,
                    &setup_mnemonic_input,
                    &setup_backup_input,
                    setup_error_message.as_deref(),
                    setup_success_message.as_deref(),
                );
            })?;
            return Ok(());
        }

        // Normal mode - collect all data needed for drawing before borrowing terminal
        let config_network_name = self.config.network.name.clone();
        let active_tab = self.active_tab;
        let status_message = self.status_message.clone();
        let accounts = self.accounts_component.accounts.clone();
        let selected_index = self.accounts_component.selected_index;
        let tip_block_number = self.tip_block_number;
        // Rotate address on every frame when spinning, but only if visible
        if self.receive_component.is_spinning
            && matches!(self.active_tab, Tab::Accounts | Tab::Receive)
        {
            self.receive_component.rotate_address();
        }
        let receive_account = self.receive_component.account.clone();
        let receive_one_time_address = self.receive_component.one_time_address.clone();
        let receive_is_spinning = self.receive_component.is_spinning;
        let send_account = self.send_component.account.clone();
        let send_recipient = self.send_component.recipient.clone();
        let send_amount = self.send_component.amount.clone();
        let send_address_type = self.send_component.detect_address_type();
        let send_focused_field = self.send_component.focused_field;
        let send_is_editing = self.send_component.is_editing;
        let send_error_message = self.send_component.error_message.clone();
        let send_success_message = self.send_component.success_message.clone();
        let send_mode = self.send_component.mode;
        let send_passphrase_input = self.send_component.passphrase_input.clone();
        // Settings component data
        let settings_current_network = self.settings_component.current_network.clone();
        let settings_mode = self.settings_component.mode;
        let settings_section = self.settings_component.section;
        let settings_wallet_index = self.settings_component.wallet_index;
        let settings_network_index = self.settings_component.network_index;
        let settings_backup_string = self.settings_component.backup_string.clone();
        let settings_error_message = self.settings_component.error_message.clone();
        let settings_success_message = self.settings_component.success_message.clone();
        let settings_passphrase_input = self.settings_component.passphrase_input.clone();
        // Tokens component data
        let tokens_account = self.tokens_component.account.clone();
        let tokens_balances = self.tokens_component.balances.clone();
        let tokens_selected_index = self.tokens_component.selected_index;
        let tokens_mode = self.tokens_component.mode;
        let tokens_list_focus = self.tokens_component.list_focus;
        let tokens_selected_operation = self.tokens_component.selected_operation;
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
        let tokens_passphrase_input = self.tokens_component.passphrase_input.clone();
        let tokens_pending_action = self.tokens_component.pending_action;
        // History component data
        let history_transactions = self.history_component.transactions.clone();
        let history_selected_index = self.history_component.selected_index;
        let history_account = self.history_component.account.clone();
        // Dev mode data
        let dev_mode = self.dev_mode;
        let indexer_synced = self.indexer_synced;
        let dev_account = self.dev_component.as_ref().and_then(|d| d.account.clone());
        let dev_checkpoint = self.dev_component.as_ref().and_then(|d| d.checkpoint);
        let dev_auto_mining = self
            .dev_component
            .as_ref()
            .map(|d| d.auto_mining)
            .unwrap_or(false);
        let dev_mining_interval = self
            .dev_component
            .as_ref()
            .map(|d| d.mining_interval)
            .unwrap_or(3);
        let dev_miner_balance = self.dev_component.as_ref().and_then(|d| d.miner_balance);
        let dev_faucet_amount = self
            .dev_component
            .as_ref()
            .map(|d| d.faucet_amount.clone())
            .unwrap_or_default();
        let dev_is_editing = self
            .dev_component
            .as_ref()
            .map(|d| d.is_editing)
            .unwrap_or(false);
        let dev_selected_operation = self
            .dev_component
            .as_ref()
            .map(|d| d.selected_operation)
            .unwrap_or(0);
        let dev_error_message = self
            .dev_component
            .as_ref()
            .and_then(|d| d.error_message.clone());
        let dev_success_message = self
            .dev_component
            .as_ref()
            .and_then(|d| d.success_message.clone());

        // Pre-compute layout to save tab area for mouse click detection
        let size = self.tui.terminal.size()?;
        let terminal_area = Rect::new(0, 0, size.width, size.height);
        let layout_chunks = Layout::vertical([
            Constraint::Length(3), // Header
            Constraint::Length(3), // Tabs
            Constraint::Min(0),    // Content
            Constraint::Length(3), // Status
        ])
        .split(terminal_area);
        self.tab_area = layout_chunks[1];

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
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ));
                // Show indexer sync status
                let sync_status = if indexer_synced {
                    "Synced"
                } else {
                    "Syncing..."
                };
                let sync_color = if indexer_synced {
                    Color::Green
                } else {
                    Color::Yellow
                };
                header_spans.push(Span::raw("  "));
                header_spans.push(Span::styled(
                    format!("Indexer: {}", sync_status),
                    Style::default().fg(sync_color),
                ));
            }
            let title = Paragraph::new(vec![Line::from(header_spans)]).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(title, chunks[0]);

            // Draw tabs
            let titles: Vec<Line> = Tab::all(dev_mode).iter().map(|t| t.title()).collect();

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
                        settings_mode,
                        settings_section,
                        settings_wallet_index,
                        settings_network_index,
                        settings_backup_string.as_deref(),
                        settings_error_message.as_deref(),
                        settings_success_message.as_deref(),
                        &settings_passphrase_input,
                    );
                }
                Tab::Accounts => {
                    AccountsComponent::draw_static(
                        f,
                        chunks[2],
                        &accounts,
                        selected_index,
                        receive_one_time_address.as_deref(),
                    );
                }
                Tab::Send => {
                    SendComponent::draw_static(
                        f,
                        chunks[2],
                        send_account.as_ref(),
                        &send_recipient,
                        &send_amount,
                        send_address_type,
                        send_focused_field,
                        send_is_editing,
                        send_error_message.as_deref(),
                        send_success_message.as_deref(),
                        send_mode,
                        &send_passphrase_input,
                    );
                }
                Tab::Receive => {
                    ReceiveComponent::draw_static(
                        f,
                        chunks[2],
                        receive_account.as_ref(),
                        receive_one_time_address.as_deref(),
                        receive_is_spinning,
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
                        tokens_list_focus,
                        tokens_selected_operation,
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
                        &tokens_passphrase_input,
                        tokens_pending_action,
                    );
                }
                Tab::History => {
                    HistoryComponent::draw_static(
                        f,
                        chunks[2],
                        &history_transactions,
                        history_selected_index,
                        history_account.as_ref(),
                    );
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
                        dev_selected_operation,
                        dev_error_message.as_deref(),
                        dev_success_message.as_deref(),
                    );
                }
            }

            // Draw status
            let tip_str = tip_block_number
                .map(|n| format!("Block: {}", n))
                .unwrap_or_else(|| "Block: -".to_string());
            let underline = Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::UNDERLINED);
            let dim = Style::default().fg(Color::DarkGray);
            let status = Paragraph::new(vec![Line::from(vec![
                Span::styled("Status: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&status_message, Style::default().fg(Color::Green)),
                Span::raw("  |  "),
                Span::styled(&tip_str, Style::default().fg(Color::Yellow)),
                Span::raw("  |  "),
                Span::styled("F", underline),
                Span::styled("ull Rescan ", dim),
                Span::styled("Q", underline),
                Span::styled("uit", dim),
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
        let titles: Vec<Line> = Tab::all(self.dev_mode).iter().map(|t| t.title()).collect();

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
        let underline = Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::UNDERLINED);
        let dim = Style::default().fg(Color::DarkGray);
        let status = Paragraph::new(vec![Line::from(vec![
            Span::styled("Status: ", dim),
            Span::styled(&self.status_message, Style::default().fg(Color::Green)),
            Span::raw("  |  "),
            Span::styled("Q", underline),
            Span::styled("uit [?]Help [Tab]Switch", dim),
        ])])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(status, area);
    }
}
