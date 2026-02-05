use std::{
    io::{self, stdout, Stdout},
    ops::{Deref, DerefMut},
    time::Duration,
};

use color_eyre::eyre::Result;
use crossterm::{
    cursor,
    event::{
        DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
        Event as CrosstermEvent, EventStream, KeyEvent, KeyEventKind, MouseEvent,
    },
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::{FutureExt, StreamExt};
use ratatui::backend::CrosstermBackend;
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

pub type Frame<'a> = ratatui::Frame<'a>;

#[derive(Clone, Debug)]
pub enum Event {
    Init,
    Quit,
    Error,
    Closed,
    Tick,
    Render,
    FocusGained,
    FocusLost,
    Paste(String),
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),
}

pub struct Tui {
    pub terminal: ratatui::Terminal<CrosstermBackend<Stdout>>,
    pub task: JoinHandle<()>,
    pub event_rx: UnboundedReceiver<Event>,
    pub event_tx: UnboundedSender<Event>,
    pub frame_rate: f64,
    pub tick_rate: f64,
    pub mouse: bool,
    pub paste: bool,
}

impl Tui {
    pub fn new() -> Result<Self> {
        let terminal = ratatui::Terminal::new(CrosstermBackend::new(stdout()))?;
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(async {});
        let frame_rate = 60.0;
        let tick_rate = 4.0;
        let mouse = false;
        let paste = false;
        Ok(Self {
            terminal,
            task,
            event_rx,
            event_tx,
            frame_rate,
            tick_rate,
            mouse,
            paste,
        })
    }

    pub fn tick_rate(mut self, tick_rate: f64) -> Self {
        self.tick_rate = tick_rate;
        self
    }

    pub fn frame_rate(mut self, frame_rate: f64) -> Self {
        self.frame_rate = frame_rate;
        self
    }

    pub fn mouse(mut self, mouse: bool) -> Self {
        self.mouse = mouse;
        self
    }

    pub fn paste(mut self, paste: bool) -> Self {
        self.paste = paste;
        self
    }

    pub fn start(&mut self) {
        let tick_delay = Duration::from_secs_f64(1.0 / self.tick_rate);
        let render_delay = Duration::from_secs_f64(1.0 / self.frame_rate);
        self.cancel();
        self.task = tokio::spawn(Self::event_loop(
            self.event_tx.clone(),
            tick_delay,
            render_delay,
        ));
    }

    async fn event_loop(tx: UnboundedSender<Event>, tick_delay: Duration, render_delay: Duration) {
        let mut reader = EventStream::new();
        let mut tick_interval = tokio::time::interval(tick_delay);
        let mut render_interval = tokio::time::interval(render_delay);
        tx.send(Event::Init).unwrap();
        loop {
            let tick_future = tick_interval.tick();
            let render_future = render_interval.tick();
            let crossterm_event = reader.next().fuse();
            tokio::select! {
                _ = tick_future => {
                    tx.send(Event::Tick).unwrap();
                }
                _ = render_future => {
                    tx.send(Event::Render).unwrap();
                }
                maybe_event = crossterm_event => {
                    match maybe_event {
                        Some(Ok(event)) => {
                            match event {
                                CrosstermEvent::Key(key) => {
                                    if key.kind == KeyEventKind::Press {
                                        tx.send(Event::Key(key)).unwrap();
                                    }
                                },
                                CrosstermEvent::Mouse(mouse) => {
                                    tx.send(Event::Mouse(mouse)).unwrap();
                                },
                                CrosstermEvent::Resize(x, y) => {
                                    tx.send(Event::Resize(x, y)).unwrap();
                                },
                                CrosstermEvent::FocusLost => {
                                    tx.send(Event::FocusLost).unwrap();
                                },
                                CrosstermEvent::FocusGained => {
                                    tx.send(Event::FocusGained).unwrap();
                                },
                                CrosstermEvent::Paste(s) => {
                                    tx.send(Event::Paste(s)).unwrap();
                                },
                            }
                        }
                        Some(Err(_)) => {
                            tx.send(Event::Error).unwrap();
                        }
                        None => {}
                    }
                }
            }
        }
    }

    pub fn enter(&mut self) -> Result<()> {
        crossterm::execute!(io::stdout(), EnterAlternateScreen, cursor::Hide)?;
        enable_raw_mode()?;
        if self.mouse {
            crossterm::execute!(stdout(), EnableMouseCapture)?;
        }
        if self.paste {
            crossterm::execute!(stdout(), EnableBracketedPaste)?;
        }
        self.start();
        Ok(())
    }

    pub fn exit(&mut self) -> Result<()> {
        self.cancel();
        if crossterm::terminal::is_raw_mode_enabled()? {
            self.flush()?;
            if self.paste {
                crossterm::execute!(stdout(), DisableBracketedPaste)?;
            }
            if self.mouse {
                crossterm::execute!(stdout(), DisableMouseCapture)?;
            }
            crossterm::execute!(io::stdout(), LeaveAlternateScreen, cursor::Show)?;
            disable_raw_mode()?;
        }
        Ok(())
    }

    pub fn cancel(&self) {
        self.task.abort();
    }

    pub fn suspend(&mut self) -> Result<()> {
        self.exit()?;
        #[cfg(not(windows))]
        signal_hook::low_level::raise(signal_hook::consts::signal::SIGTSTP)?;
        Ok(())
    }

    pub fn resume(&mut self) -> Result<()> {
        self.enter()?;
        Ok(())
    }

    pub async fn next(&mut self) -> Option<Event> {
        self.event_rx.recv().await
    }
}

impl Deref for Tui {
    type Target = ratatui::Terminal<CrosstermBackend<Stdout>>;

    fn deref(&self) -> &Self::Target {
        &self.terminal
    }
}

impl DerefMut for Tui {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.terminal
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        self.exit().unwrap();
    }
}

pub fn restore() -> Result<()> {
    if crossterm::terminal::is_raw_mode_enabled()? {
        crossterm::execute!(
            std::io::stdout(),
            DisableBracketedPaste,
            DisableMouseCapture,
            LeaveAlternateScreen,
            cursor::Show
        )?;
        disable_raw_mode()?;
    }
    Ok(())
}
