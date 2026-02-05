use color_eyre::eyre::Result;
use tracing::error;
use tracing_error::ErrorLayer;
use tracing_subscriber::{self, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

use crate::config::get_data_dir;

pub fn init() -> Result<()> {
    let data_dir = get_data_dir();
    std::fs::create_dir_all(&data_dir)?;
    let log_path = data_dir.join("obscell-wallet.log");

    let log_file = std::fs::File::create(log_path)?;

    let file_subscriber = tracing_subscriber::fmt::layer()
        .with_file(true)
        .with_line_number(true)
        .with_writer(log_file)
        .with_target(false)
        .with_ansi(false)
        .with_filter(EnvFilter::from_default_env().add_directive("obscell_wallet=debug".parse()?));

    tracing_subscriber::registry()
        .with(file_subscriber)
        .with(ErrorLayer::default())
        .init();

    Ok(())
}

/// Log a panic message and backtrace.
pub fn log_panic(panic: &std::panic::PanicHookInfo) {
    let msg = match panic.payload().downcast_ref::<&'static str>() {
        Some(s) => *s,
        None => match panic.payload().downcast_ref::<String>() {
            Some(s) => s.as_str(),
            None => "unknown panic payload",
        },
    };

    let location = panic.location().map_or_else(
        || "unknown location".to_string(),
        |loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()),
    );

    error!("Panic occurred: {} at {}", msg, location);
}
