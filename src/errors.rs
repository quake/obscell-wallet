use std::panic;

use color_eyre::{config::HookBuilder, eyre::Result};

use crate::logging::log_panic;
use crate::tui;

/// Install panic and error hooks.
pub fn install_hooks() -> Result<()> {
    let (panic_hook, eyre_hook) = HookBuilder::default()
        .panic_section(format!(
            "This is a bug. Consider reporting it at {}",
            env!("CARGO_PKG_REPOSITORY")
        ))
        .capture_span_trace_by_default(false)
        .display_location_section(true)
        .display_env_section(false)
        .into_hooks();

    // Install color-eyre panic hook
    let panic_hook = panic_hook.into_panic_hook();
    panic::set_hook(Box::new(move |panic_info| {
        log_panic(panic_info);
        if let Err(e) = tui::restore() {
            eprintln!("Failed to restore terminal: {e}");
        }
        panic_hook(panic_info);
    }));

    // Install color-eyre error hook
    eyre_hook.install()?;

    Ok(())
}
