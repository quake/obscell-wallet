pub mod accounts;
pub mod dev;
pub mod history;
pub mod receive;
pub mod send;
pub mod settings;
pub mod tokens;

use color_eyre::eyre::Result;
use crossterm::event::KeyEvent;
use ratatui::layout::Rect;

use crate::tui::Frame;

/// A component is a reusable UI element that can handle events and render itself.
pub trait Component {
    fn handle_key_event(&mut self, key: KeyEvent) -> Result<()>;
    fn draw(&mut self, f: &mut Frame, area: Rect);
}
